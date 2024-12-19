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
                ["1-QmbtpbTPGFVQFsx6pxyoDgboRTuAUjckeiZ6bMuSjiTZD9","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"Qmc9sXqmUSnyt3C14nF5bsEkwTgJDwLwCUUKpFZt6iP55y","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:Qmc9sXqmUSnyt3C14nF5bsEkwTgJDwLwCUUKpFZt6iP55y:127.0.0.1%3A54858","verificationMethod":[{"id":"did:tdw:Qmc9sXqmUSnyt3C14nF5bsEkwTgJDwLwCUUKpFZt6iP55y:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:Qmc9sXqmUSnyt3C14nF5bsEkwTgJDwLwCUUKpFZt6iP55y:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:Qmc9sXqmUSnyt3C14nF5bsEkwTgJDwLwCUUKpFZt6iP55y:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:Qmc9sXqmUSnyt3C14nF5bsEkwTgJDwLwCUUKpFZt6iP55y:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmbtpbTPGFVQFsx6pxyoDgboRTuAUjckeiZ6bMuSjiTZD9","proofValue":"z4fGWtRv6cPkwpxK4SqKY7L4FhC7XveEGNi6wgqfWjU7tRCZRzBs5SwTveWNiDtWD1Ywp6D2xd3beNeKCorHs1grQ"}]
                ["1-QmNUUFD2zy14QGcKgm8iNjS74Tg17Rbesojq6JvphcyDNZ","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmV3wigdKXJMnRb5dEuo9LT6xzYZy31w22TSNEbhARENyd","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmV3wigdKXJMnRb5dEuo9LT6xzYZy31w22TSNEbhARENyd:127.0.0.1%3A54858:123456789","verificationMethod":[{"id":"did:tdw:QmV3wigdKXJMnRb5dEuo9LT6xzYZy31w22TSNEbhARENyd:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmV3wigdKXJMnRb5dEuo9LT6xzYZy31w22TSNEbhARENyd:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmV3wigdKXJMnRb5dEuo9LT6xzYZy31w22TSNEbhARENyd:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmV3wigdKXJMnRb5dEuo9LT6xzYZy31w22TSNEbhARENyd:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmNUUFD2zy14QGcKgm8iNjS74Tg17Rbesojq6JvphcyDNZ","proofValue":"z2aV38ahWUwukPjm13nMX45wBYytuEUmpZj2oEm8UWsftgxQJfZ2GfZ5p8r8Ramo3sx4uhFipYYe1es1WWqYzUCuL"}]
                ["1-QmYjcig2CdTpyQvKc13JyGS6VW6fvpvi9TPaCcZtEEFiQk","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRFN7t8xsKqaCYSiWgtMw7zLc8rAhNSL31cTm6Z91XuVo","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRFN7t8xsKqaCYSiWgtMw7zLc8rAhNSL31cTm6Z91XuVo:127.0.0.1%3A54858:123456789:123456789","verificationMethod":[{"id":"did:tdw:QmRFN7t8xsKqaCYSiWgtMw7zLc8rAhNSL31cTm6Z91XuVo:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRFN7t8xsKqaCYSiWgtMw7zLc8rAhNSL31cTm6Z91XuVo:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRFN7t8xsKqaCYSiWgtMw7zLc8rAhNSL31cTm6Z91XuVo:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRFN7t8xsKqaCYSiWgtMw7zLc8rAhNSL31cTm6Z91XuVo:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmYjcig2CdTpyQvKc13JyGS6VW6fvpvi9TPaCcZtEEFiQk","proofValue":"z4x4YZqEUy4C6cjmLCPLm4sfTPLVYxtJhuabeywr7kHMmGiXWTikuqE8x2fP8Fr2p5YCnVbhFymh8u4tqtJjEivsE"}]
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
                ["1-QmbH1F9JVM42gUytimjxuAqQAd4vwKwSXZ6CNt84zSfpaS","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmT3dpCUVKyTVgjtVQqz8HszJMT296f8HTzmqDSbwaizZs","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmT3dpCUVKyTVgjtVQqz8HszJMT296f8HTzmqDSbwaizZs:127.0.0.1%3A54858","verificationMethod":[{"id":"did:tdw:QmT3dpCUVKyTVgjtVQqz8HszJMT296f8HTzmqDSbwaizZs:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:QmT3dpCUVKyTVgjtVQqz8HszJMT296f8HTzmqDSbwaizZs:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmT3dpCUVKyTVgjtVQqz8HszJMT296f8HTzmqDSbwaizZs:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:QmT3dpCUVKyTVgjtVQqz8HszJMT296f8HTzmqDSbwaizZs:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:QmT3dpCUVKyTVgjtVQqz8HszJMT296f8HTzmqDSbwaizZs:127.0.0.1%3A54858#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmT3dpCUVKyTVgjtVQqz8HszJMT296f8HTzmqDSbwaizZs:127.0.0.1%3A54858","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:QmT3dpCUVKyTVgjtVQqz8HszJMT296f8HTzmqDSbwaizZs:127.0.0.1%3A54858#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmT3dpCUVKyTVgjtVQqz8HszJMT296f8HTzmqDSbwaizZs:127.0.0.1%3A54858","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmbH1F9JVM42gUytimjxuAqQAd4vwKwSXZ6CNt84zSfpaS","proofValue":"z57RL8TR6PLSwQbge9hs2RdcKHWnBg8HwS1hSpsBdvWtw6pSY3ahyzDjVBiuReuMPVZXJvNW8zpZD192rZqpqpxW8"}]
                ["1-QmUru8ckwkzBHUGLLMgyMLTL9HFCtHxXkxPd7zoFtRWb3t","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmUY2WYQ1caYkMHJ9YtSwjTb2jjFwUSLDqW3wH3F7xNcet","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmUY2WYQ1caYkMHJ9YtSwjTb2jjFwUSLDqW3wH3F7xNcet:127.0.0.1%3A54858:123456789","verificationMethod":[{"id":"did:tdw:QmUY2WYQ1caYkMHJ9YtSwjTb2jjFwUSLDqW3wH3F7xNcet:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmUY2WYQ1caYkMHJ9YtSwjTb2jjFwUSLDqW3wH3F7xNcet:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmUY2WYQ1caYkMHJ9YtSwjTb2jjFwUSLDqW3wH3F7xNcet:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmUY2WYQ1caYkMHJ9YtSwjTb2jjFwUSLDqW3wH3F7xNcet:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:QmUY2WYQ1caYkMHJ9YtSwjTb2jjFwUSLDqW3wH3F7xNcet:127.0.0.1%3A54858:123456789#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmUY2WYQ1caYkMHJ9YtSwjTb2jjFwUSLDqW3wH3F7xNcet:127.0.0.1%3A54858:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:QmUY2WYQ1caYkMHJ9YtSwjTb2jjFwUSLDqW3wH3F7xNcet:127.0.0.1%3A54858:123456789#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmUY2WYQ1caYkMHJ9YtSwjTb2jjFwUSLDqW3wH3F7xNcet:127.0.0.1%3A54858:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmUru8ckwkzBHUGLLMgyMLTL9HFCtHxXkxPd7zoFtRWb3t","proofValue":"z2q7neMDSyKnsk7dNAqgfx5AwDQFmPeF8HBvFYLz81pEowbgWyvGqesPsN6U2TarYfZyExK8tH7AxDGpuTwbsZLRE"}]
                ["1-QmNhVgtX6h7PhM27sEzpK5WoBDXEF1pCD81EuVG38VgqQn","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRFK4Jvcawu63NaDPHXDdvs5MrrxsMad4XXVFYybXwvr6","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRFK4Jvcawu63NaDPHXDdvs5MrrxsMad4XXVFYybXwvr6:127.0.0.1%3A54858:123456789:123456789","verificationMethod":[{"id":"did:tdw:QmRFK4Jvcawu63NaDPHXDdvs5MrrxsMad4XXVFYybXwvr6:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRFK4Jvcawu63NaDPHXDdvs5MrrxsMad4XXVFYybXwvr6:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRFK4Jvcawu63NaDPHXDdvs5MrrxsMad4XXVFYybXwvr6:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRFK4Jvcawu63NaDPHXDdvs5MrrxsMad4XXVFYybXwvr6:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:QmRFK4Jvcawu63NaDPHXDdvs5MrrxsMad4XXVFYybXwvr6:127.0.0.1%3A54858:123456789:123456789#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRFK4Jvcawu63NaDPHXDdvs5MrrxsMad4XXVFYybXwvr6:127.0.0.1%3A54858:123456789:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:QmRFK4Jvcawu63NaDPHXDdvs5MrrxsMad4XXVFYybXwvr6:127.0.0.1%3A54858:123456789:123456789#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRFK4Jvcawu63NaDPHXDdvs5MrrxsMad4XXVFYybXwvr6:127.0.0.1%3A54858:123456789:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmNhVgtX6h7PhM27sEzpK5WoBDXEF1pCD81EuVG38VgqQn","proofValue":"z2sM5AU6op8mYxCXpZGKY7jEKCFCyE6mkpbCvr7hHbLVsiKxbdcty4UuCvgZ2qAca6y5ozDvfCBvWjnjW1EBMoUKz"}]
                """.contains(didLogEntry));
    }
}
