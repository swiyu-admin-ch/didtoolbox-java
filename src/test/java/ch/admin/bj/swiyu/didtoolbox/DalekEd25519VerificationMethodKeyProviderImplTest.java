package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("PMD")
class DalekEd25519VerificationMethodKeyProviderImplTest extends AbstractUtilTestBase {

    private static Collection<Object[]> keysSignature() {
        return Arrays.asList(new String[][]{
                {TEST_KEYS[0][0], TEST_KEYS[0][1], "8514c1f5e8a1ec90b131985703ed3ce0f637107e0b3f60a1ec412c7e1c0455c3a0be5668e9a04af5eaab1c93cefbf7ed0f2d592c86624966f86c43cc49429e0f"},
                {TEST_KEYS[1][0], TEST_KEYS[1][1], "7390ad2dd39f5f6a689b78a7d1e9f9c7288350194822426e5f32ce866673d3a3f86a64c0cbdc9a5cc816e961e9b3f211d2f89e62a3cca0de0a89f03c7cd45309"},
                {TEST_KEYS[2][0], TEST_KEYS[2][1], "706b8c08e91f6342d9ddf6d3a8a57e584653f726d683348998da4dd748f27a9c1be8114bafe6bff80d93c0c63c7a456b294b9985e09e9fca99c3249cc741350f"},
        });
    }

    private static Collection<Object[]> keyMessageSignature() {
        return Arrays.asList(new String[][]{
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Errare humanum est", "7bbe819b9a9e2c1e89ee280a7741a978b8a8a7e260a2a818711828776a54dde389615af6aaf4b6a9508d315751b6a15ebe7c3e363cddb25583259975e4b73d04"},
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Acta non verba", "921fb5033ce365eb1b741c12f07f6f69b770019a2a34eb3222d8734441cd9efc6268d0068f08c282d0d2d2357443846d50f62405c06d7907994fb8d8045ebe0c"},
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Fortes fortuna adiuvat", "c7e0ffc73efab191057207843eed955c892101465783e9d34b5336a04adb01099ec461913e1aa020df57872bfad534f88db0dea4d6383a0bafefc2a4d0a70208"},
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Per aspera ad astra", "0d984e0a250486fbd4e3e1dd3b3599ab693692e3dcc962d472e85a2bf73007308d79d7d951d9e99b72b72a579445b5a2623b7b26bb7be82933e9c38e61bbae03"},
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Corgito ergo sum", "479b27179469ecd4518fb047166d2513a6808b55482610cf8b9ff39558b63ea3c44cd254660f6b7185d870d95c9f0a650345612031d4b6c154d341caae59c402"},
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Carpe diem", "9f3c0f2517201cc461de1758d5797e2d36cfee08b592d39b9eac6149c4ff8586a1a517b713dfc8264d42bd52d2a9026443cd9b8ef35889dbbd6bdbc0326f8e0f"},
        });
    }

    @Test
    void testGetVerificationKeyMultibaseExample() {

        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
        assertDoesNotThrow(() -> {
            assertEquals("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
                    new DalekEd25519VerificationMethodKeyProviderImpl(
                            "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq")
                            .getVerificationKeyMultibase());
        });
    }

    @DisplayName("Displaying verification key in multibase format")
    @ParameterizedTest(name = "Verification key: {1}")
    @MethodSource("keysSignature")
    void testGetVerificationKeyMultibase(String privateKeyMultibase, String publicKeyMultibase, String expected) {

        assertDoesNotThrow(() -> {
            assertEquals(publicKeyMultibase, new DalekEd25519VerificationMethodKeyProviderImpl(
                    privateKeyMultibase)
                    .getVerificationKeyMultibase());
        });
    }

    @DisplayName("Verifying using various existing keys")
    @ParameterizedTest(name = "Verifying using key: {0}")
    @MethodSource("keysSignature")
    public void testVerifyUsingKeys(String privateKeyMultibase, String publicKeyMultibase, String expected) {

        assertDoesNotThrow(() -> {
            assertTrue(new DalekEd25519VerificationMethodKeyProviderImpl(privateKeyMultibase)
                    .verifyStrict("The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8), HexFormat.of().parseHex(expected))); // MUT
        });
    }

    @DisplayName("Signing using various existing keys")
    @ParameterizedTest(name = "Signing using key: {0}")
    @MethodSource("keyMessageSignature")
    public void testSignUsingKeys(String privateKeyMultibase, String publicKeyMultibase, String message, String expected) {

        assertDoesNotThrow(() -> {
            var msg = message.getBytes(StandardCharsets.UTF_8);

            var signer = new DalekEd25519VerificationMethodKeyProviderImpl(privateKeyMultibase);

            var signed = HexFormat.of().formatHex(signer.generateSignature(msg)); // MUT

            assertNotNull(signed);
            assertEquals(128, signed.length());
            assertEquals(expected, signed);

            // checkpoint
            assertTrue(signer.verifyStrict(msg, HexFormat.of().parseHex(expected)));
        });
    }

    @Test
    public void testAddEddsaJcs2022DataIntegrityProof() { // according to https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022

        assertDoesNotThrow(() -> {
            // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
            var credentialsWithProof = new DalekEd25519VerificationMethodKeyProviderImpl("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq")
                    .addEddsaJcs2022DataIntegrityProof(
                            // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-credential-without-proof-0
                            """
                                    {
                                         "@context": [
                                             "https://www.w3.org/ns/credentials/v2",
                                             "https://www.w3.org/ns/credentials/examples/v2"
                                         ],
                                         "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
                                         "type": ["VerifiableCredential", "AlumniCredential"],
                                         "name": "Alumni Credential",
                                         "description": "A minimum viable example of an Alumni Credential.",
                                         "issuer": "https://vc.example/issuers/5678",
                                         "validFrom": "2023-01-01T00:00:00Z",
                                         "credentialSubject": {
                                             "id": "did:example:abcdefgh",
                                             "alumniOf": "The School of Examples"
                                         }
                                    }
                                    """,
                            null, // CAUTION The original PROOF_OPTIONS_DOCUMENT features NO proof's challenge!
                            "assertionMethod",
                            ZonedDateTime.parse("2023-02-24T23:36:38Z")); // MUT

            // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-base58-btc-1
            assertEquals("z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX",
                    JsonParser.parseString(credentialsWithProof).getAsJsonObject().get("proof").getAsJsonArray().get(0).getAsJsonObject().get("proofValue").getAsString());
        });
    }
}