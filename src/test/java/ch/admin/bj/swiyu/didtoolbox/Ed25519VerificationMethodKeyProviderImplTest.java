package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all the PMD warnings in this (test) class
@SuppressWarnings("PMD")
class Ed25519VerificationMethodKeyProviderImplTest extends AbstractUtilTestBase {

    /*
    @BeforeAll
    static void initAll() {

    }
     */

    private static Collection<Object[]> keyMessageSignature() {
        return Arrays.asList(new String[][]{{"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Errare humanum est", "7bbe819b9a9e2c1e89ee280a7741a978b8a8a7e260a2a818711828776a54dde389615af6aaf4b6a9508d315751b6a15ebe7c3e363cddb25583259975e4b73d04"}, {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Acta non verba", "921fb5033ce365eb1b741c12f07f6f69b770019a2a34eb3222d8734441cd9efc6268d0068f08c282d0d2d2357443846d50f62405c06d7907994fb8d8045ebe0c"}, {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Fortes fortuna adiuvat", "c7e0ffc73efab191057207843eed955c892101465783e9d34b5336a04adb01099ec461913e1aa020df57872bfad534f88db0dea4d6383a0bafefc2a4d0a70208"}, {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Per aspera ad astra", "0d984e0a250486fbd4e3e1dd3b3599ab693692e3dcc962d472e85a2bf73007308d79d7d951d9e99b72b72a579445b5a2623b7b26bb7be82933e9c38e61bbae03"}, {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Corgito ergo sum", "479b27179469ecd4518fb047166d2513a6808b55482610cf8b9ff39558b63ea3c44cd254660f6b7185d870d95c9f0a650345612031d4b6c154d341caae59c402"}, {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Carpe diem", "9f3c0f2517201cc461de1758d5797e2d36cfee08b592d39b9eac6149c4ff8586a1a517b713dfc8264d42bd52d2a9026443cd9b8ef35889dbbd6bdbc0326f8e0f"},});
    }

    @DisplayName("Signing using a newly generated key")
    @ParameterizedTest(name = "Signing: {2}")
    @MethodSource("keyMessageSignature")
    public void testSign(String unusedPrivateKeyMultibase, String unusedPublicKeyMultibase, String message) {

        var signed = HexFormat.of().formatHex(new Ed25519VerificationMethodKeyProviderImpl().generateSignature(message.getBytes(StandardCharsets.UTF_8))); // MUT

        assertNotNull(signed);
        assertEquals(128, signed.length());
        //assertEquals(expected, signed);
    }

    @Test
    void testWritePrivateKeyAsPem() throws IOException {

        File tempFile = File.createTempFile("myprivatekey", ".pem");
        tempFile.deleteOnExit();

        (new Ed25519VerificationMethodKeyProviderImpl()).writePrivateKeyAsPem(tempFile); // MUT

        assertNotEquals(0, Files.size(tempFile.toPath())); // must not be empty, at least
        assertDoesNotThrow(() -> {
            PemUtils.readPEMFile(tempFile); // and must be a regular PEM file (content-wise), of course
        });
        assertEquals(3, Files.lines(tempFile.toPath(), StandardCharsets.UTF_8).count());
    }

    @Test
    void testWritePublicKeyAsPem() throws IOException {

        File tempFile = File.createTempFile("mypublickey", ".pem");
        tempFile.deleteOnExit();

        (new Ed25519VerificationMethodKeyProviderImpl()).writePublicKeyAsPem(tempFile); // MUT

        assertNotEquals(0, Files.size(tempFile.toPath())); // must not be empty, at least
        assertDoesNotThrow(() -> {
            PemUtils.readPEMFile(tempFile); // and must be a regular PEM file (content-wise), of course
        });
        assertEquals(3, Files.lines(tempFile.toPath(), StandardCharsets.UTF_8).count());
    }

    @Test
    public void testLoadFromJKSThrowsException() {
        // the key does not exists
        assertThrowsExactly(KeyException.class, () -> new Ed25519VerificationMethodKeyProviderImpl(Files.newInputStream(Path.of("src/test/data/mykeystore.jks")), "changeit", "non-existing-alias", "whatever"));

        // wrong keystore password
        assertThrowsExactly(IOException.class, () -> new Ed25519VerificationMethodKeyProviderImpl(Files.newInputStream(Path.of("src/test/data/mykeystore.jks")), "wrong", "whatever", "whatever"));

        // wrong key (recovery) password
        //assertThrowsExactly(UnrecoverableKeyException.class,
        //        () -> new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias", "wrong"));

        // wrong file format
        assertThrowsExactly(IOException.class, () -> new Ed25519VerificationMethodKeyProviderImpl(Files.newInputStream(Path.of("src/test/data/com.securosys.primus.jce.credentials.properties")), "whatever", "whatever", "whatever"));
    }

    @DisplayName("Signing using key from a JKS")
    @ParameterizedTest(name = "Signing: {2}")
    @MethodSource("keyMessageSignature")
    public void testSignUsingJKS(String unusedPrivateKeyMultibase, String unusedPublicKeyMultibase, String message, String expected) throws UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyException {

        String signed = HexFormat.of().formatHex(new Ed25519VerificationMethodKeyProviderImpl(Files.newInputStream(Path.of("src/test/data/mykeystore.jks")), "changeit", "myalias", "changeit").generateSignature(message.getBytes(StandardCharsets.UTF_8))); // MUT

        assertNotNull(signed);
        assertEquals(128, signed.length());
        assertEquals(expected, signed);
    }

    @DisplayName("Verifying using key from a JKS")
    @ParameterizedTest(name = "Verifying signed message: {2}")
    @MethodSource("keyMessageSignature")
    public void testVerifyUsingJKS(String unusedPrivateKeyMultibase, String unusedPublicKeyMultibase, String message, String expected) throws UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyException {

        boolean verified = new Ed25519VerificationMethodKeyProviderImpl(Files.newInputStream(Path.of("src/test/data/mykeystore.jks")), "changeit", "myalias", "changeit").verify(message.getBytes(StandardCharsets.UTF_8), HexFormat.of().parseHex(expected)); // MUT

        assertTrue(verified);
    }

    @DisplayName("Signing using key from PEM files")
    @ParameterizedTest(name = "Signing: {2}")
    @MethodSource("keyMessageSignature")
    public void testSignUsingPemKeys(String unusedPrivateKey, String unusedPublicKey, String message, String expected) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, DidSidekicksException {

        String signed = HexFormat.of().formatHex(new Ed25519VerificationMethodKeyProviderImpl(Files.newBufferedReader(Path.of("src/test/data/private.pem")), Files.newBufferedReader(Path.of("src/test/data/public.pem"))).generateSignature(message.getBytes(StandardCharsets.UTF_8))); // MUT

        assertNotNull(signed);
        assertEquals(128, signed.length());
        assertEquals(expected, signed);

        // Using another ("hybrid") signature

        signed = HexFormat.of().formatHex(new Ed25519VerificationMethodKeyProviderImpl(Files.newBufferedReader(Path.of("src/test/data/private.pem")), PemUtils.readEd25519PublicKeyPemFileToMultibase(Path.of("src/test/data/public.pem"))).generateSignature(message.getBytes(StandardCharsets.UTF_8))); // MUT

        assertNotNull(signed);
        assertEquals(128, signed.length());
        assertEquals(expected, signed);
    }

    @DisplayName("Verifying using PEM keys")
    @ParameterizedTest(name = "Verifying signed message: {2}")
    @MethodSource("keyMessageSignature")
    public void testVerifyUsingPemKeys(String unusedPrivateKeyMultibase, String unusedPublicKeyMultibase, String message, String expected) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, DidSidekicksException {

        boolean verified = new Ed25519VerificationMethodKeyProviderImpl(Files.newBufferedReader(Path.of("src/test/data/private.pem")), Files.newBufferedReader(Path.of("src/test/data/public.pem"))).verify(message.getBytes(StandardCharsets.UTF_8), HexFormat.of().parseHex(expected)); // MUT

        assertTrue(verified);

        // Using another ("hybrid") signature

        verified = new Ed25519VerificationMethodKeyProviderImpl(Files.newBufferedReader(Path.of("src/test/data/private.pem")), PemUtils.readEd25519PublicKeyPemFileToMultibase(Path.of("src/test/data/public.pem"))).verify(message.getBytes(StandardCharsets.UTF_8), HexFormat.of().parseHex(expected)); // MUT

        assertTrue(verified);
    }

    @Test
    public void testThrowsIllegalArgumentException() {

        assertThrowsExactly(IllegalArgumentException.class, () -> {
            new Ed25519VerificationMethodKeyProviderImpl(Files.newBufferedReader(Path.of("src/test/data/public.pem")), Files.newBufferedReader(Path.of("src/test/data/private.pem"))); // keys swapped, both wrong
        });

        assertThrowsExactly(IllegalArgumentException.class, () -> {
            new Ed25519VerificationMethodKeyProviderImpl(Files.newBufferedReader(Path.of("src/test/data/private.pem")), Files.newBufferedReader(Path.of("src/test/data/private.pem"))); // wrong public key PEM file
        });

        assertThrowsExactly(IllegalArgumentException.class, () -> {
            new Ed25519VerificationMethodKeyProviderImpl(Files.newBufferedReader(Path.of("src/test/data/public.pem")), Files.newBufferedReader(Path.of("src/test/data/public.pem"))); // wrong private key PEM file
        });
    }

    @Test
    public void testAddProof() { // according to https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022

        assertDoesNotThrow(() -> {

            var privateKeyPemFile = Files.createTempFile("myprivatekey", "");
            var publicKeyPemFile = Files.createTempFile("mypublickey", "");
            // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
            var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq");
            cryptoSuite.writePkcs8PemFile(privateKeyPemFile);
            cryptoSuite.writePublicKeyPemFile(publicKeyPemFile);

            // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
            var credentialsWithProof = new Ed25519VerificationMethodKeyProviderImpl(
                    Files.newBufferedReader(privateKeyPemFile), Files.newBufferedReader(publicKeyPemFile))
                    .addProof(
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
                                    """, null, // CAUTION The original PROOF_OPTIONS_DOCUMENT features NO proof's challenge!
                            "assertionMethod", ZonedDateTime.parse("2023-02-24T23:36:38Z")); // MUT

            // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-base58-btc-1
            assertEquals("z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX", JsonParser.parseString(credentialsWithProof).getAsJsonObject().get("proof").getAsJsonArray().get(0).getAsJsonObject().get("proofValue").getAsString());

            Files.deleteIfExists(privateKeyPemFile);
            Files.deleteIfExists(publicKeyPemFile);
        });
    }
}