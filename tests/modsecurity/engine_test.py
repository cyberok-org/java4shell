"""Replay synthetic cases to a static Apache server INSIDE an offline container.

No Java backend, remote target, published port or production traffic is used.
Print only case names and rule IDs; raw engine logs remain in the temporary container.
"""
import http.client
from pathlib import Path
import re
import subprocess
import sys
import time

from test_modsecurity import cases


def request(headers, body):
    connection = http.client.HTTPConnection('127.0.0.1', 8080, timeout=5)
    try:
        connection.request('POST', '/synthetic', body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def main():
    check = subprocess.run(['apache2', '-f', '/test/apache.conf', '-t'],
                           capture_output=True, text=True)
    if check.returncode:
        raise RuntimeError('Apache configuration check failed: ' + check.stderr)
    versions = subprocess.check_output(
        ['dpkg-query', '-W', '-f=${Package} ${Version}\n', 'apache2', 'libapache2-mod-security2'],
        text=True)
    print(versions.strip())
    process = subprocess.Popen(['apache2', '-f', '/test/apache.conf', '-DFOREGROUND'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                baseline = request({}, '')
                break
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError('Apache exited during startup')
                time.sleep(0.05)
        else:
            raise RuntimeError('Apache did not become ready')
        logfile = Path('/tmp/java4shell-error.log')
        for name, headers, body, expected in cases():
            offset = logfile.stat().st_size
            status = request(headers, body)
            time.sleep(0.01)
            with logfile.open('rb') as stream:
                stream.seek(offset)
                log = stream.read().decode(errors='replace')
            actual = {int(value) for value in re.findall(r'\[id "(114938\d+)"\]', log)}
            if actual != expected or status != baseline:
                raise AssertionError('%s: IDs %s expected %s; status %s baseline %s' %
                                     (name, sorted(actual), sorted(expected), status, baseline))
            print('PASS %s IDs=%s' % (name, sorted(actual)))
        print('PASS: Apache/ModSecurity syntax and %d HTTP cases; log-only behavior preserved.' % len(cases()))
        return 0
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == '__main__':
    sys.exit(main())
