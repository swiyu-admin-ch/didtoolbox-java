package ch.admin.bj.swiyu.didtoolbox;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.FileInputStream;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class TdwCreatorTest {

    private static Collection<Object[]> domainPath() {
        return Arrays.asList(new String[][]{
                {"https://127.0.0.1:54858", null},
                {"https://127.0.0.1:54858", "123456789"},
                {"https://127.0.0.1:54858", "123456789/123456789"},
        });
    }

    @DisplayName("Building TDW log entry for various domain(:path) variants")
    @ParameterizedTest(name = "For domain {0} and path {1}")
    @MethodSource("domainPath")
    public void testBuild(String domain, String path) {

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .signer(new Ed25519SignerVerifier())
                    .build()
                    .create(domain, path, ZonedDateTime.now()); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertNotNull(didLogEntry);
    }

    @DisplayName("Building TDW log entry for various domain(:path) variants using Java Keystore (JKS)")
    @ParameterizedTest(name = "For domain {0} and path {1}")
    @MethodSource("domainPath")
    public void testBuildUsingJKS(String domain, String path) {

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .signer(new Ed25519SignerVerifier(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .build()
                    .create(domain, path, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertNotNull(didLogEntry);

        //System.out.println(didLogEntry);

        assertTrue("""
                ["1-QmTkJyYmkxQ4p2XBELyFJUFXfUSW7H8Bq15wW8DmKVFnCj","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmTkJyYmkxQ4p2XBELyFJUFXfUSW7H8Bq15wW8DmKVFnCj","proofValue":"z39MuvNWn8B21E938G63dB16Um9fbo2vcoeWNre5QTMMevFWjZWurhqg5WzNbHMCFT7V36rkNH1ejkbniNA1aXMbA"}]
                ["1-QmVX1PWZUcmQmYYVBTnJ9THQeTt5yZ8TecVLKHZVJq6bT9","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmVX1PWZUcmQmYYVBTnJ9THQeTt5yZ8TecVLKHZVJq6bT9","proofValue":"z4p9xxdTg7XeMCzeL685aETxYhcvGWrswc2t19WHHGAgQ9H27f4DrBx8UuLvkCbE9DZPD7TXXeCMJqWt5fu4VRGsw"}]
                ["1-QmYUVGgfWMnuRsZgnSMPF13TSNSuV58HGHRQimvGoEfbDn","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmYUVGgfWMnuRsZgnSMPF13TSNSuV58HGHRQimvGoEfbDn","proofValue":"z4ottbZjAuXUQFQmNhCcjoyS78b1u7U2uKnRfEEk1QJfcCKXQoy5uUAKwpebRg68tKvuYz93PgHB4iBHk2ds2Hc8q"}]
                """.contains(didLogEntry));
    }

    @DisplayName("Building TDW log entry for various domain(:path) variants (incl. assertion) using existing keys")
    @ParameterizedTest(name = "For domain {0} and path {1}")
    @MethodSource("domainPath")
    public void testBuildUsingKeysWithAssertionMethods(String domain, String path) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .signer(new Ed25519SignerVerifier(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .assertionMethods(Map.of(
                            "myAssertionKey1", new AssertionMethodInput(null),
                            "myAssertionKey2", new AssertionMethodInput("z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP")
                    ))
                    .build()
                    .create(domain, path, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertNotNull(didLogEntry);

        //System.out.println(didLogEntry);

        assertTrue("""
                ["1-QmXKHqSEohWgHRbiZMacDvUDff6h6cwcawhdbPy75yCzYv","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmXKHqSEohWgHRbiZMacDvUDff6h6cwcawhdbPy75yCzYv","proofValue":"z4GAPTeficPR7iw3s9MnPJ42ia9y1V2rsL8KdGgnHKQwWCYMVQteEDormbQjnPfQYfrATF5kBUf7k2wm2p5ZuCM4Q"}]
                ["1-QmQGcVhHjnRY7vYC5wjJyJFs613RF76Pn9ZQXqGkhiQHND","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmQGcVhHjnRY7vYC5wjJyJFs613RF76Pn9ZQXqGkhiQHND","proofValue":"z5TiX1e24eEBZ2VLD1QhAeE3C9igNvz8GFGRsx9kzzssExkCLfW5TFuae9XkUjAh1UJH3rkiyvthfQzKGDp42n9UH"}]
                ["1-QmcJcdzqe82ijse9EKSchj2ZnfF5PVPaJsyfYsUk4tgyrZ","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmcJcdzqe82ijse9EKSchj2ZnfF5PVPaJsyfYsUk4tgyrZ","proofValue":"z27VK6XYxxanev361TpqSK4cxt23QrWD5QWPURwWw2T4i8Tdj3spr9o3QYap5eNotennfdi2gvgB7BDhrNpqn64pe"}]
                """.contains(didLogEntry));
    }
}
