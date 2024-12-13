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
                ["1-Q21SBmnGCpdDbZyQQm7DzCzdfKnMcLTjbDyAmPwqWRJCNTsXsPXq6tiZVJcQLnvXoPZRZ66zpixQaBCswCMKcYMov","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"Q2zFa3ksnTK9nahf2vX6aoaF6KHCAjvQWriKBhTx5o1J2HoYAaRuwocm9NwwPDGfa311CYMihFwa4iRFwK5VJfCUy","portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:Q2zFa3ksnTK9nahf2vX6aoaF6KHCAjvQWriKBhTx5o1J2HoYAaRuwocm9NwwPDGfa311CYMihFwa4iRFwK5VJfCUy:127.0.0.1%3A54858","verificationMethod":[{"id":"did:tdw:Q2zFa3ksnTK9nahf2vX6aoaF6KHCAjvQWriKBhTx5o1J2HoYAaRuwocm9NwwPDGfa311CYMihFwa4iRFwK5VJfCUy:127.0.0.1%3A54858#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q2zFa3ksnTK9nahf2vX6aoaF6KHCAjvQWriKBhTx5o1J2HoYAaRuwocm9NwwPDGfa311CYMihFwa4iRFwK5VJfCUy:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:Q2zFa3ksnTK9nahf2vX6aoaF6KHCAjvQWriKBhTx5o1J2HoYAaRuwocm9NwwPDGfa311CYMihFwa4iRFwK5VJfCUy:127.0.0.1%3A54858#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q2zFa3ksnTK9nahf2vX6aoaF6KHCAjvQWriKBhTx5o1J2HoYAaRuwocm9NwwPDGfa311CYMihFwa4iRFwK5VJfCUy:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"controller":["did:tdw:Q2zFa3ksnTK9nahf2vX6aoaF6KHCAjvQWriKBhTx5o1J2HoYAaRuwocm9NwwPDGfa311CYMihFwa4iRFwK5VJfCUy:127.0.0.1%3A54858"]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:tdw:Q2zFa3ksnTK9nahf2vX6aoaF6KHCAjvQWriKBhTx5o1J2HoYAaRuwocm9NwwPDGfa311CYMihFwa4iRFwK5VJfCUy:127.0.0.1%3A54858#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","proofPurpose":"authentication","challenge":"1-Q21SBmnGCpdDbZyQQm7DzCzdfKnMcLTjbDyAmPwqWRJCNTsXsPXq6tiZVJcQLnvXoPZRZ66zpixQaBCswCMKcYMov","proofValue":"z25eNpT8cFxSzmvVtGdEhZtyC1ZRUuEQFytc5VBomS2PBZLh3qcXKfdDNgHgtTQhg5eUaP61Xi5mcBwsMBGjDVa6i"}]
                ["1-Q24hPtZ4XP6J1MuhPFADA49DYFHqsQmZcYsQP1fVkAzbpbKMAMa1EjLYvE9K7V5PF1QzfhheELuXRugipQHxQUMuQ","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"Q23XZR32ttdiQe527Dm14QEdKwaH2bzxVKZntYqqbirCsTwTF6EuDCCAr6VGAkPPiNXfi9bVgsK2JDFz3AtD8r1Fs","portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:Q23XZR32ttdiQe527Dm14QEdKwaH2bzxVKZntYqqbirCsTwTF6EuDCCAr6VGAkPPiNXfi9bVgsK2JDFz3AtD8r1Fs:127.0.0.1%3A54858:123456789","verificationMethod":[{"id":"did:tdw:Q23XZR32ttdiQe527Dm14QEdKwaH2bzxVKZntYqqbirCsTwTF6EuDCCAr6VGAkPPiNXfi9bVgsK2JDFz3AtD8r1Fs:127.0.0.1%3A54858:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q23XZR32ttdiQe527Dm14QEdKwaH2bzxVKZntYqqbirCsTwTF6EuDCCAr6VGAkPPiNXfi9bVgsK2JDFz3AtD8r1Fs:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:Q23XZR32ttdiQe527Dm14QEdKwaH2bzxVKZntYqqbirCsTwTF6EuDCCAr6VGAkPPiNXfi9bVgsK2JDFz3AtD8r1Fs:127.0.0.1%3A54858:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q23XZR32ttdiQe527Dm14QEdKwaH2bzxVKZntYqqbirCsTwTF6EuDCCAr6VGAkPPiNXfi9bVgsK2JDFz3AtD8r1Fs:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"controller":["did:tdw:Q23XZR32ttdiQe527Dm14QEdKwaH2bzxVKZntYqqbirCsTwTF6EuDCCAr6VGAkPPiNXfi9bVgsK2JDFz3AtD8r1Fs:127.0.0.1%3A54858:123456789"]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:tdw:Q23XZR32ttdiQe527Dm14QEdKwaH2bzxVKZntYqqbirCsTwTF6EuDCCAr6VGAkPPiNXfi9bVgsK2JDFz3AtD8r1Fs:127.0.0.1%3A54858:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","proofPurpose":"authentication","challenge":"1-Q24hPtZ4XP6J1MuhPFADA49DYFHqsQmZcYsQP1fVkAzbpbKMAMa1EjLYvE9K7V5PF1QzfhheELuXRugipQHxQUMuQ","proofValue":"zsB8BqxKmgSZ4Jk4dvzheG35on4r2XvrK8VHHPQHbxzjDsevYQnEWUt3nmrW18PrH4Frbj7mckkYujm4ubD5uLJU"}]
                ["1-Q28PjFinx2GEr8GWc2LTCDJ6C3LvwPGThdqd6ErrwyC832Lq8sJE3Qha5V3zft7cu6Jph5o33baHfc7vVHjau7BCo","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"Q271L3BFvWWJBbnvk3gJY2dEc91ARPajK5qnEMKkWtWVtnCQE8eMvBQCzG9S7tas7D3wATeDjVCykTXdd6idxzwv1","portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:Q271L3BFvWWJBbnvk3gJY2dEc91ARPajK5qnEMKkWtWVtnCQE8eMvBQCzG9S7tas7D3wATeDjVCykTXdd6idxzwv1:127.0.0.1%3A54858:123456789:123456789","verificationMethod":[{"id":"did:tdw:Q271L3BFvWWJBbnvk3gJY2dEc91ARPajK5qnEMKkWtWVtnCQE8eMvBQCzG9S7tas7D3wATeDjVCykTXdd6idxzwv1:127.0.0.1%3A54858:123456789:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q271L3BFvWWJBbnvk3gJY2dEc91ARPajK5qnEMKkWtWVtnCQE8eMvBQCzG9S7tas7D3wATeDjVCykTXdd6idxzwv1:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:Q271L3BFvWWJBbnvk3gJY2dEc91ARPajK5qnEMKkWtWVtnCQE8eMvBQCzG9S7tas7D3wATeDjVCykTXdd6idxzwv1:127.0.0.1%3A54858:123456789:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q271L3BFvWWJBbnvk3gJY2dEc91ARPajK5qnEMKkWtWVtnCQE8eMvBQCzG9S7tas7D3wATeDjVCykTXdd6idxzwv1:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"controller":["did:tdw:Q271L3BFvWWJBbnvk3gJY2dEc91ARPajK5qnEMKkWtWVtnCQE8eMvBQCzG9S7tas7D3wATeDjVCykTXdd6idxzwv1:127.0.0.1%3A54858:123456789:123456789"]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:tdw:Q271L3BFvWWJBbnvk3gJY2dEc91ARPajK5qnEMKkWtWVtnCQE8eMvBQCzG9S7tas7D3wATeDjVCykTXdd6idxzwv1:127.0.0.1%3A54858:123456789:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","proofPurpose":"authentication","challenge":"1-Q28PjFinx2GEr8GWc2LTCDJ6C3LvwPGThdqd6ErrwyC832Lq8sJE3Qha5V3zft7cu6Jph5o33baHfc7vVHjau7BCo","proofValue":"z4MPL4gwm8SdtPVxQ6EJgyGtrU43ByoWJ1xBvVXfTT6sD8U3hkQRcRMX9qE3wSDWTuEBmQpy2hXD6mkzKR9BB4stM"}]
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
                ["1-Q22NMY8gnjLLfyTfP2pynPKmyhFh8taj9kixGtGiWPtYWDqtymjKK1i7g9xqwGHKJ9i3Gz6imoLD4zokwqitTEdLG","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy","portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy:127.0.0.1%3A54858","verificationMethod":[{"id":"did:tdw:Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy:127.0.0.1%3A54858#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy:127.0.0.1%3A54858#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy:127.0.0.1%3A54858","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy:127.0.0.1%3A54858#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy:127.0.0.1%3A54858","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy:127.0.0.1%3A54858#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy:127.0.0.1%3A54858","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"controller":["did:tdw:Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy:127.0.0.1%3A54858"]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:tdw:Q24gZ98puosUNkSHbpZW5nW31UWFGbvsQGZMDtDBDJ77TUWTsjEaZrinLUczMeyr9b7THhm6by9JPQ8D5VQY26KCy:127.0.0.1%3A54858#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","proofPurpose":"authentication","challenge":"1-Q22NMY8gnjLLfyTfP2pynPKmyhFh8taj9kixGtGiWPtYWDqtymjKK1i7g9xqwGHKJ9i3Gz6imoLD4zokwqitTEdLG","proofValue":"z3hH5UJQQuvDvNoAuU3DEkeCeDSxtjVH8F7L2EUtSJuadz9oihT9JrcVhHDKpn1LDwRRM8wsZo1tD7x7VtamPw8uz"}]
                ["1-Q33W9vmMfc1t6js2zxybnEyyRkQktE2JvNyZcYm9ouGhyGzmVHcsaNuef6euYqyvbEqCaWa9B4B1vb4hdJp2pS5Dr","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK","portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK:127.0.0.1%3A54858:123456789","verificationMethod":[{"id":"did:tdw:Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK:127.0.0.1%3A54858:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK:127.0.0.1%3A54858:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK:127.0.0.1%3A54858:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK:127.0.0.1%3A54858:123456789#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK:127.0.0.1%3A54858:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK:127.0.0.1%3A54858:123456789#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK:127.0.0.1%3A54858:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"controller":["did:tdw:Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK:127.0.0.1%3A54858:123456789"]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:tdw:Q264UDJTb7KnPRa1fQNqnNsWxQKozQxjjS2dfXd2ynrhs2ELfHETcNpiS1ykhxSeaRWKL7av7JwuYfYCqR2CUpyiK:127.0.0.1%3A54858:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","proofPurpose":"authentication","challenge":"1-Q33W9vmMfc1t6js2zxybnEyyRkQktE2JvNyZcYm9ouGhyGzmVHcsaNuef6euYqyvbEqCaWa9B4B1vb4hdJp2pS5Dr","proofValue":"z2vRSd1QfyPwmdeAfsRUAYfK94RjvPa9K51vztYHkDD6yMy6qBynxKUzCXhGgEpGKX6tDSZiBqyFQ4mrRvqKwVEau"}]
                ["1-Q272AtsrKkb8Y8e1ckVJhgtMQx41gyHnKABiH7fd2oRbdzQaJ2mTYw6mvzpcYxdedn8SRuvns5Z47Zw1Gtb4DDspw","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC","portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC:127.0.0.1%3A54858:123456789:123456789","verificationMethod":[{"id":"did:tdw:Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC:127.0.0.1%3A54858:123456789:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"authentication":[{"id":"did:tdw:Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC:127.0.0.1%3A54858:123456789:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","controller":"did:tdw:Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC:127.0.0.1%3A54858:123456789:123456789","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"assertionMethod":[{"id":"did:tdw:Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC:127.0.0.1%3A54858:123456789:123456789#myAssertionKey1","type":"Ed25519VerificationKey2020","controller":"did:tdw:Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC:127.0.0.1%3A54858:123456789:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},{"id":"did:tdw:Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC:127.0.0.1%3A54858:123456789:123456789#myAssertionKey2","type":"Ed25519VerificationKey2020","controller":"did:tdw:Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC:127.0.0.1%3A54858:123456789:123456789","publicKeyMultibase":"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"}],"controller":["did:tdw:Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC:127.0.0.1%3A54858:123456789:123456789"]}},{"type":"DataIntegrityProof","cryptoSuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:tdw:Q21E6pvy5cqG7aSxLNwWpJwNnjGnZdZno7hBuRAHfjWsNn8PQnSyPpXxLzSu4caxH4sBxXU943BB5kaK4MWawLpVC:127.0.0.1%3A54858:123456789:123456789#z28Be9B8CtiAgQf9HEptrkaYeL7ssrvhsuLoL5JYyTq7oFjzWLVcatysn2dKsimtUcSzj9QeKuLGyGT1vk1zfiJyv","proofPurpose":"authentication","challenge":"1-Q272AtsrKkb8Y8e1ckVJhgtMQx41gyHnKABiH7fd2oRbdzQaJ2mTYw6mvzpcYxdedn8SRuvns5Z47Zw1Gtb4DDspw","proofValue":"z4EpGbbWGKt7u77AHn1XQvpH3caVjysLeSBLwj1C1fauecEgR8khkhXZCeed88ivfyN6iMb3usg7x2DX1cJTz9GEm"}]
                """.contains(didLogEntry));
    }
}
