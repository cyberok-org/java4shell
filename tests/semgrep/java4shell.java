import java.util.Base64;
import java.net.URLDecoder;
import org.springframework.util.Base64Utils;
import com.google.protobuf.util.JsonFormat;
import org.yaml.snakeyaml.Yaml;

class ReviewExamples {
    byte[] reused;
    void examples(byte[] source, Base64.Decoder decoder) {
        // ruleid: java4shell-two-argument-decode
        Base64.getDecoder().decode(source, reused);
        // ruleid: java4shell-two-argument-decode, java4shell-field-destination-review
        java.util.Base64.getUrlDecoder().decode(source, this.reused);
        // Fresh buffers remain review candidates; the rule does not assert reuse.
        // ruleid: java4shell-two-argument-decode, java4shell-inline-buffer-review
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

class ExpandedReviewExamples {
    byte[] retained;

    void destinations(byte[] source, Base64.Decoder decoder, int capacity,
                      OtherDecoder otherDecoder, Holder owner) {
        // The threshold is a triage heuristic, not a vulnerability boundary.
        // ok: java4shell-inline-large-buffer-review
        // ruleid: java4shell-two-argument-decode, java4shell-inline-buffer-review
        Base64.getDecoder().decode(source, new byte[1024]);
        // ruleid: java4shell-two-argument-decode, java4shell-inline-buffer-review, java4shell-inline-large-buffer-review
        Base64.getDecoder().decode(source, new byte[1025]);
        // ruleid: java4shell-two-argument-decode, java4shell-inline-buffer-review, java4shell-inline-large-buffer-review
        java.util.Base64.getUrlDecoder().decode(source, new byte[4096]);
        // A runtime-dependent capacity is still a review candidate.
        // ok: java4shell-inline-large-buffer-review
        // ruleid: java4shell-two-argument-decode, java4shell-inline-buffer-review
        Base64.getDecoder().decode(source, new byte[capacity]);
        // ruleid: java4shell-decoder-variable-review, java4shell-inline-buffer-review, java4shell-inline-large-buffer-review
        decoder.decode(source, new byte[4096]);
        // ruleid: java4shell-decoder-variable-review, java4shell-field-destination-review
        decoder.decode(source, this.retained);
        // ruleid: java4shell-two-argument-decode, java4shell-field-destination-review
        Base64.getDecoder().decode(source, owner.retained);

        byte[] buffer = new byte[4096];
        // The name rule intentionally also matches a fresh local buffer.
        // ruleid: java4shell-two-argument-decode, java4shell-buffer-name-review
        Base64.getUrlDecoder().decode(source, buffer);
        byte[] sharedStorage = owner.retained;
        // ruleid: java4shell-decoder-variable-review, java4shell-buffer-name-review
        decoder.decode(source, sharedStorage);

        // ok: java4shell-field-destination-review, java4shell-buffer-name-review, java4shell-decoder-variable-review
        otherDecoder.decode(source, owner.buf);
        // ok: java4shell-inline-buffer-review, java4shell-inline-large-buffer-review
        otherDecoder.decode(source, new byte[4096]);
        // ok: java4shell-two-argument-decode, java4shell-inline-buffer-review, java4shell-inline-large-buffer-review
        Base64.getMimeDecoder().decode(source, new byte[4096]);
        // ok: java4shell-field-destination-review, java4shell-buffer-name-review
        Base64.getMimeDecoder().decode(source, owner.buf);

        // Typed receivers require manual factory review, including MIME aliases.
        Base64.Decoder mimeAlias = Base64.getMimeDecoder();
        // ruleid: java4shell-decoder-variable-review, java4shell-field-destination-review
        mimeAlias.decode(source, this.retained);
    }

    void libraries(byte[] source, String text, JsonFormat.Parser parser,
                   Object builder, Yaml yaml, Object constructor) {
        // ruleid: java4shell-spring-base64utils-inventory
        Base64Utils.decode(source);
        // ruleid: java4shell-spring-base64utils-inventory
        org.springframework.util.Base64Utils.decodeFromString(text);
        // ok: java4shell-spring-base64utils-inventory
        example.Base64Utils.decode(source);
        // ruleid: java4shell-protobuf-json-review
        JsonFormat.parser().merge(text, builder);
        // ruleid: java4shell-protobuf-json-review
        parser.merge(text, builder);
        // ok: java4shell-protobuf-json-review
        example.JsonFormat.parser().merge(text, builder);
        // ruleid: java4shell-snakeyaml-load-review
        new Yaml().load(text);
        // ruleid: java4shell-snakeyaml-load-review
        new org.yaml.snakeyaml.Yaml(constructor).load(text);
        // ruleid: java4shell-snakeyaml-load-review
        yaml.load(text);
        // ok: java4shell-snakeyaml-load-review
        new example.Yaml().load(text);
    }
}
