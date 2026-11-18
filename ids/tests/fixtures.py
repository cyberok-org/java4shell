"""Build a PCAP file only. No sockets, subprocesses or JVM execution.

Packet construction derives from jsik22/java4shell-detection under ../LICENSE.
Extended with explicit expectations, shared WAF cases and TCP fragmentation.
"""
import json
import struct
import sys

from cases import all_cases
from upstream_fixtures import _pkt


def main(out_pcap, out_index):
    client, server = '192.0.2.10', '198.51.100.20'
    response = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'
    frames, index = [], {}
    for n, item in enumerate(all_cases()):
        port, cs, ss = 20000 + n, 1000, 5000
        request = item['request']
        index[port] = {k: v for k, v in item.items() if k != 'request'}
        packets = [(client, server, port, 80, cs, 0, 0x02, b''),
                   (server, client, 80, port, ss, cs + 1, 0x12, b''),
                   (client, server, port, 80, cs + 1, ss + 1, 0x10, b'')]
        start = 0
        for end in sorted(set(item['splits'] + [len(request)])):
            if not start < end <= len(request):
                raise ValueError('Invalid split point')
            packets.append((client, server, port, 80, cs + 1 + start, ss + 1, 0x18, request[start:end]))
            packets.append((server, client, 80, port, ss + 1, cs + 1 + end, 0x10, b''))
            start = end
        cs += 1 + len(request)
        packets.extend([(server, client, 80, port, ss + 1, cs, 0x18, response),
                        (client, server, port, 80, cs, ss + 1 + len(response), 0x10, b''),
                        (client, server, port, 80, cs, ss + 1 + len(response), 0x11, b''),
                        (server, client, 80, port, ss + 1 + len(response), cs + 1, 0x11, b''),
                        (client, server, port, 80, cs + 1, ss + 2 + len(response), 0x10, b'')])
        frames.extend(_pkt(*packet) for packet in packets)
    with open(out_pcap, 'wb') as stream:
        stream.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for n, frame in enumerate(frames):
            stream.write(struct.pack('<IIII', 1763424000 + n // 1000, (n % 1000) * 1000, len(frame), len(frame)) + frame)
    with open(out_index, 'w') as stream:
        json.dump(index, stream, indent=2)
    print('Generated %d cases and %d frames; no network traffic sent.' % (len(index), len(frames)))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
