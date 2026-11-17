import java.util.Base64;
import java.net.URLDecoder;

class ReviewExamples {
    byte[] reused;
    void examples(byte[] source, Base64.Decoder decoder) {
        // ruleid: java4shell-two-argument-decode
        Base64.getDecoder().decode(source, reused);
        // ruleid: java4shell-two-argument-decode
        java.util.Base64.getUrlDecoder().decode(source, this.reused);
        // Fresh buffers remain review candidates; the rule does not assert reuse.
        // ruleid: java4shell-two-argument-decode
        Base64.getDecoder().decode(source, new byte[100]);
        // ruleid: java4shell-decoder-variable-review
        decoder.decode(source, reused);
        // ruleid: java4shell-one-argument-inventory
        Base64.getDecoder().decode(source);
        // ruleid: java4shell-one-argument-inventory
        Base64.getUrlDecoder().decode(source);
        // ok: java4shell-two-argument-decode, java4shell-one-argument-inventory
        Base64.getMimeDecoder().decode(source, reused);
        // ok: java4shell-two-argument-decode, java4shell-one-argument-inventory
        Base64.getMimeDecoder().decode(source);
        // ok: java4shell-two-argument-decode, java4shell-decoder-variable-review
        URLDecoder.decode("example", "UTF-8");
        // ok: java4shell-one-argument-inventory
        org.apache.commons.codec.binary.Base64.decodeBase64(source);
    }
}
