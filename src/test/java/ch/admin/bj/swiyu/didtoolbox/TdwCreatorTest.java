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
                    .signer(new Signer())
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
                    .signer(new Signer(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .build()
                    .create(domain, path, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertNotNull(didLogEntry);

        //System.out.println(didLogEntry);

        assertTrue("""
                ["1-QmTkJyYmkxQ4p2XBELyFJUFXfUSW7H8Bq15wW8DmKVFnCj","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmTkJyYmkxQ4p2XBELyFJUFXfUSW7H8Bq15wW8DmKVFnCj","proofValue":"z5tt7WeMFwPEdM4JMFeQ4M7yeP7p1Z2j5KyoSbCcLysfqjgxXptPd4iLn9auJ37Wee6Pmf3LYSqf9p2K1aLEZvdrv"}]
                ["1-QmVX1PWZUcmQmYYVBTnJ9THQeTt5yZ8TecVLKHZVJq6bT9","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmVX1PWZUcmQmYYVBTnJ9THQeTt5yZ8TecVLKHZVJq6bT9","proofValue":"zzyTBywn32NSEYx93a248w241Ewy4Zeqp8tkaBtj97PeBxgAnKD5mb7ApimyVtJaf6wdowihiV84YVLYtXyff74z"}]
                ["1-QmYUVGgfWMnuRsZgnSMPF13TSNSuV58HGHRQimvGoEfbDn","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmYUVGgfWMnuRsZgnSMPF13TSNSuV58HGHRQimvGoEfbDn","proofValue":"z3JHnii5qWczhmHLMpuiojuD1tnAPyZEoBNWoyxmmoBqCJ4kK1uGE4DCLwNjDbhHBuHVxrcyRFLS63MU5G8JiMGFr"}]
                """.contains(didLogEntry));
    }

    @DisplayName("Building TDW log entry for various domain(:path) variants (incl. assertion) using existing keys")
    @ParameterizedTest(name = "For domain {0} and path {1}")
    @MethodSource("domainPath")
    public void testBuildUsingKeysWithAssertionMethods(String domain, String path) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .signer(new Signer(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
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
                ["1-QmXKHqSEohWgHRbiZMacDvUDff6h6cwcawhdbPy75yCzYv","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmXKHqSEohWgHRbiZMacDvUDff6h6cwcawhdbPy75yCzYv","proofValue":"z3AJgLWEz5md9FGYgZBtHbBmhtq4q7mWg4DLgYtyqYx5VP9mjTRYQx9qvidRJ8WTBAHtvmHKxV2WL7CUeGPoQFquc"}]
                ["1-QmQGcVhHjnRY7vYC5wjJyJFs613RF76Pn9ZQXqGkhiQHND","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmQGcVhHjnRY7vYC5wjJyJFs613RF76Pn9ZQXqGkhiQHND","proofValue":"z37MEJrhCkJ2zW4e3mSPe5Z76Rk1pCXZknt8UMtGHmPeUJP9xhhaqW2qww46F7TvP6Ku7SyVpdPTNyCyST76eNTAU"}]
                ["1-QmcJcdzqe82ijse9EKSchj2ZnfF5PVPaJsyfYsUk4tgyrZ","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","verificationMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#KsXDA8UP","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:QmRJwoi992UZCFF9QERk7Zxc8dcZjbq7j85fLPtRmqcQDA:127.0.0.1%3A54858:123456789:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmcJcdzqe82ijse9EKSchj2ZnfF5PVPaJsyfYsUk4tgyrZ","proofValue":"zQ4tTDtXxVBudhtfRb9aXxAkgPDCXGLAkgjJjvFmHPkvxADbPLB8Bz6gFbFFM3kmfG5TKDZWH3L65nbzvHcuG4MZ"}]
                """.contains(didLogEntry));
    }
}
