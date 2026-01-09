package ch.admin.bj.swiyu.didtoolbox;

import org.bouncycastle.util.encoders.Hex;
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
import java.util.Arrays;
import java.util.Collection;

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
        return Arrays.asList(new String[][]{
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Errare humanum est", "7bbe819b9a9e2c1e89ee280a7741a978b8a8a7e260a2a818711828776a54dde389615af6aaf4b6a9508d315751b6a15ebe7c3e363cddb25583259975e4b73d04"},
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Acta non verba", "921fb5033ce365eb1b741c12f07f6f69b770019a2a34eb3222d8734441cd9efc6268d0068f08c282d0d2d2357443846d50f62405c06d7907994fb8d8045ebe0c"},
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Fortes fortuna adiuvat", "c7e0ffc73efab191057207843eed955c892101465783e9d34b5336a04adb01099ec461913e1aa020df57872bfad534f88db0dea4d6383a0bafefc2a4d0a70208"},
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Per aspera ad astra", "0d984e0a250486fbd4e3e1dd3b3599ab693692e3dcc962d472e85a2bf73007308d79d7d951d9e99b72b72a579445b5a2623b7b26bb7be82933e9c38e61bbae03"},
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Corgito ergo sum", "479b27179469ecd4518fb047166d2513a6808b55482610cf8b9ff39558b63ea3c44cd254660f6b7185d870d95c9f0a650345612031d4b6c154d341caae59c402"},
                {"z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD", "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", "Carpe diem", "9f3c0f2517201cc461de1758d5797e2d36cfee08b592d39b9eac6149c4ff8586a1a517b713dfc8264d42bd52d2a9026443cd9b8ef35889dbbd6bdbc0326f8e0f"},
        });
    }

    @DisplayName("Signing using a newly generated key")
    @ParameterizedTest(name = "Signing: {2}")
    @MethodSource("keyMessageSignature")
    public void testSign(String unusedPrivateKeyMultibase, String unusedPublicKeyMultibase, String message) {

        var signed = Hex.toHexString(new Ed25519VerificationMethodKeyProviderImpl()
                .generateSignature(message.getBytes(StandardCharsets.UTF_8))); // MUT

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
            PemUtils.parsePEMFile(tempFile); // and must be a regular PEM file (content-wise), of course
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
            PemUtils.parsePEMFile(tempFile); // and must be a regular PEM file (content-wise), of course
        });
        assertEquals(3, Files.lines(tempFile.toPath(), StandardCharsets.UTF_8).count());
    }

    @Test
    public void testLoadFromJKSThrowsException() {
        // the key does not exists
        assertThrowsExactly(KeyException.class,
                () -> new Ed25519VerificationMethodKeyProviderImpl(Files.newInputStream(Path.of("src/test/data/mykeystore.jks")), "changeit", "non-existing-alias", "whatever"));

        // wrong keystore password
        assertThrowsExactly(IOException.class,
                () -> new Ed25519VerificationMethodKeyProviderImpl(Files.newInputStream(Path.of("src/test/data/mykeystore.jks")), "wrong", "whatever", "whatever"));

        // wrong key (recovery) password
        //assertThrowsExactly(UnrecoverableKeyException.class,
        //        () -> new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias", "wrong"));

        // wrong file format
        assertThrowsExactly(IOException.class,
                () -> new Ed25519VerificationMethodKeyProviderImpl(Files.newInputStream(Path.of("src/test/data/com.securosys.primus.jce.credentials.properties")), "whatever", "whatever", "whatever"));
    }

    @DisplayName("Signing using key from a JKS")
    @ParameterizedTest(name = "Signing: {2}")
    @MethodSource("keyMessageSignature")
    public void testSignUsingJKS(String unusedPrivateKeyMultibase, String unusedPublicKeyMultibase, String message, String expected)
            throws UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyException {

        String signed = Hex.toHexString(new Ed25519VerificationMethodKeyProviderImpl(Files.newInputStream(Path.of("src/test/data/mykeystore.jks")), "changeit", "myalias", "changeit").generateSignature(message.getBytes(StandardCharsets.UTF_8))); // MUT

        assertNotNull(signed);
        assertEquals(128, signed.length());
        assertEquals(expected, signed);
    }

    @DisplayName("Verifying using key from a JKS")
    @ParameterizedTest(name = "Verifying signed message: {2}")
    @MethodSource("keyMessageSignature")
    public void testVerifyUsingJKS(String unusedPrivateKeyMultibase, String unusedPublicKeyMultibase, String message, String expected)
            throws UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyException {

        boolean verified = new Ed25519VerificationMethodKeyProviderImpl(Files.newInputStream(Path.of("src/test/data/mykeystore.jks")), "changeit", "myalias", "changeit").verify(message.getBytes(StandardCharsets.UTF_8), Hex.decode(expected)); // MUT

        assertTrue(verified);
    }

    @DisplayName("Signing using key from PEM files")
    @ParameterizedTest(name = "Signing: {2}")
    @MethodSource("keyMessageSignature")
    public void testSignUsingPemKeys(String unusedPrivateKey, String unusedPublicKey, String message, String expected)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        String signed = Hex.toHexString(new Ed25519VerificationMethodKeyProviderImpl(
                Files.newBufferedReader(Path.of("src/test/data/private.pem")),
                Files.newBufferedReader(Path.of("src/test/data/public.pem"))).generateSignature(message.getBytes(StandardCharsets.UTF_8))); // MUT

        assertNotNull(signed);
        assertEquals(128, signed.length());
        assertEquals(expected, signed);

        // Using another ("hybrid") signature

        signed = Hex.toHexString(new Ed25519VerificationMethodKeyProviderImpl(
                Files.newBufferedReader(Path.of("src/test/data/private.pem")),
                PemUtils.parsePEMFilePublicKeyEd25519Multibase(new File("src/test/data/public.pem"))).generateSignature(message.getBytes(StandardCharsets.UTF_8))); // MUT

        assertNotNull(signed);
        assertEquals(128, signed.length());
        assertEquals(expected, signed);
    }

    @DisplayName("Verifying using PEM keys")
    @ParameterizedTest(name = "Verifying signed message: {2}")
    @MethodSource("keyMessageSignature")
    public void testVerifyUsingPemKeys(String unusedPrivateKeyMultibase, String unusedPublicKeyMultibase, String message, String expected)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        boolean verified = new Ed25519VerificationMethodKeyProviderImpl(
                Files.newBufferedReader(Path.of("src/test/data/private.pem")),
                Files.newBufferedReader(Path.of("src/test/data/public.pem"))).verify(message.getBytes(StandardCharsets.UTF_8), Hex.decode(expected)); // MUT

        assertTrue(verified);

        // Using another ("hybrid") signature

        verified = new Ed25519VerificationMethodKeyProviderImpl(
                Files.newBufferedReader(Path.of("src/test/data/private.pem")),
                PemUtils.parsePEMFilePublicKeyEd25519Multibase(new File("src/test/data/public.pem"))).verify(message.getBytes(StandardCharsets.UTF_8), Hex.decode(expected)); // MUT

        assertTrue(verified);
    }

    @Test
    public void testThrowsInvalidKeySpecException() {

        assertThrowsExactly(InvalidKeySpecException.class, () -> {
            new Ed25519VerificationMethodKeyProviderImpl(Files.newBufferedReader(Path.of("src/test/data/public.pem")), Files.newBufferedReader(Path.of("src/test/data/private.pem"))); // keys swapped, both wrong
        });

        assertThrowsExactly(InvalidKeySpecException.class, () -> {
            new Ed25519VerificationMethodKeyProviderImpl(Files.newBufferedReader(Path.of("src/test/data/private.pem")), Files.newBufferedReader(Path.of("src/test/data/private.pem"))); // wrong public key PEM file
        });

        assertThrowsExactly(InvalidKeySpecException.class, () -> {
            new Ed25519VerificationMethodKeyProviderImpl(Files.newBufferedReader(Path.of("src/test/data/public.pem")), Files.newBufferedReader(Path.of("src/test/data/public.pem"))); // wrong private key PEM file
        });
    }
}