package ch.admin.bj.swiyu;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

public class SignerTest {

    /*
    @BeforeAll
    static void initAll() {

    }
     */

    private static Collection<Object[]> keysSignature() {
        return Arrays.asList(new String[][]{
                /*
                All lines in the private/public matrix were generated using openssl command by running the following script:

                openssl genpkey -algorithm ed25519 -out private.pem
                openssl pkey -inform pem -in private.pem -outform der -out private.der
                cat private.pem | openssl pkey -pubout -outform der -out public.der
                echo "{\"$(xxd -plain -cols 32 -s -32 private.der | openssl base64 -A)\", \"$(xxd -plain -cols 32 -s -32 public.der | openssl base64 -A)\", \"\"}"
                 */
                {"ODEwOGJmY2MxOTc5OWVkNjg0YmJjNjc0ODUzNjA1NjkzMTY1NWVjNTVkM2MyYjcyMTYyZWZmNjAyYTA4Mjc5OQo", "Zjg3MGU2YzYzMzUwMjc5MDE3N2ZhODUyODVjZTI1ZDBhMDgzNDg2MmFjMzBlZjdiOTA5YTM2MjNmNTJmZTY3ZQo", "952994a86f326550f487cd2c75907c1ec037fe4aa958963e995340130dd8fff81f2bdc80090b7db7b84c1ea01e9cf4fabb593b834d2ea1cd6ecb3ad7d66b1b06"},
                {"YWRiNmIyZjFlOWRjZDRjMDgyNGZmZDRjYTVlZWViOTg4OTgyYzVhOTNhNWM5ZTBhMjU0MGEzNzliMWUxMTEwMwo", "NDY2NWFhNzEwYjU1YmVhMWRmOWViOWM0N2IxY2E0MTk4NzIzZTFiZWY4Mjg5NTU3M2U4YTNmM2Y0YWIzYjE5NQo", "5df3d762826d04ec0d9538af8bfc54ea9bb22e751ada35080f74d16f5200c2b1d98024a2abce9390973e2d8be06f4827e5135db15d245fc1c290c7ff280a6d03"},
                {"ZGNkYjQyMzI0NmM3YTZjOTY1N2I5ZjQ3ZDhjNzlhNDEzODU2MWM2MTZlYmIzY2U5NGQ5Y2E5ZjE0Y2QwMWJmZQo", "MjUxODQ3MjVjYmFkNmMzNzM2ZWE2YjNlZTI3YTgyOTRhMjRhYjZmMWQxZTI0MjU5YzlmMjE0OGRjYzZjMDRkYQo", "bc635d4159ac7c9feba3d567b3b987ec94f878ca1f5d9bddd3fc19c9f5b25fc18df63cd5358199fffe9f1309ad39cca8d5a9661a3caa10d2a44faedf9e78720b"},
                {"ZjdmYjk3N2NiNmRkNWFkNTVhYzY1NWFlYzM3NmY5OGI4ODBiMmFkOTc4MDI4ODY1ZmNiMmE3YTg5MmEyNTQ0OAo", "ZjA0NGNiYzEwMDRhODI0ZjVmMzM2NTc0YjUwNTc5MDFkOGViMzJmN2FkMmViODIzZTQyZjg1M2E2NjA2NGM5OAo", "23c1222b464c5ebb269ab83bbc08d67c003d260ebb44763e9e764f8a86298104757aa4408ade2e218a32ac9ed732f7a063a3fcb9ae2a8327ab18482c2d41d90a"},
        });
    }

    private static Collection<Object[]> keyMessageSignature() {
        return Arrays.asList(new String[][]{
                {"ZjdmYjk3N2NiNmRkNWFkNTVhYzY1NWFlYzM3NmY5OGI4ODBiMmFkOTc4MDI4ODY1ZmNiMmE3YTg5MmEyNTQ0OAo", "ZjA0NGNiYzEwMDRhODI0ZjVmMzM2NTc0YjUwNTc5MDFkOGViMzJmN2FkMmViODIzZTQyZjg1M2E2NjA2NGM5OAo", "Errare humanum est", "7bbe819b9a9e2c1e89ee280a7741a978b8a8a7e260a2a818711828776a54dde389615af6aaf4b6a9508d315751b6a15ebe7c3e363cddb25583259975e4b73d04"},
                {"ZjdmYjk3N2NiNmRkNWFkNTVhYzY1NWFlYzM3NmY5OGI4ODBiMmFkOTc4MDI4ODY1ZmNiMmE3YTg5MmEyNTQ0OAo", "ZjA0NGNiYzEwMDRhODI0ZjVmMzM2NTc0YjUwNTc5MDFkOGViMzJmN2FkMmViODIzZTQyZjg1M2E2NjA2NGM5OAo", "Acta non verba", "921fb5033ce365eb1b741c12f07f6f69b770019a2a34eb3222d8734441cd9efc6268d0068f08c282d0d2d2357443846d50f62405c06d7907994fb8d8045ebe0c"},
                {"ZjdmYjk3N2NiNmRkNWFkNTVhYzY1NWFlYzM3NmY5OGI4ODBiMmFkOTc4MDI4ODY1ZmNiMmE3YTg5MmEyNTQ0OAo", "ZjA0NGNiYzEwMDRhODI0ZjVmMzM2NTc0YjUwNTc5MDFkOGViMzJmN2FkMmViODIzZTQyZjg1M2E2NjA2NGM5OAo", "Fortes fortuna adiuvat", "c7e0ffc73efab191057207843eed955c892101465783e9d34b5336a04adb01099ec461913e1aa020df57872bfad534f88db0dea4d6383a0bafefc2a4d0a70208"},
                {"ZjdmYjk3N2NiNmRkNWFkNTVhYzY1NWFlYzM3NmY5OGI4ODBiMmFkOTc4MDI4ODY1ZmNiMmE3YTg5MmEyNTQ0OAo", "ZjA0NGNiYzEwMDRhODI0ZjVmMzM2NTc0YjUwNTc5MDFkOGViMzJmN2FkMmViODIzZTQyZjg1M2E2NjA2NGM5OAo", "Per aspera ad astra", "0d984e0a250486fbd4e3e1dd3b3599ab693692e3dcc962d472e85a2bf73007308d79d7d951d9e99b72b72a579445b5a2623b7b26bb7be82933e9c38e61bbae03"},
                {"ZjdmYjk3N2NiNmRkNWFkNTVhYzY1NWFlYzM3NmY5OGI4ODBiMmFkOTc4MDI4ODY1ZmNiMmE3YTg5MmEyNTQ0OAo", "ZjA0NGNiYzEwMDRhODI0ZjVmMzM2NTc0YjUwNTc5MDFkOGViMzJmN2FkMmViODIzZTQyZjg1M2E2NjA2NGM5OAo", "Corgito ergo sum", "479b27179469ecd4518fb047166d2513a6808b55482610cf8b9ff39558b63ea3c44cd254660f6b7185d870d95c9f0a650345612031d4b6c154d341caae59c402"},
                {"ZjdmYjk3N2NiNmRkNWFkNTVhYzY1NWFlYzM3NmY5OGI4ODBiMmFkOTc4MDI4ODY1ZmNiMmE3YTg5MmEyNTQ0OAo", "ZjA0NGNiYzEwMDRhODI0ZjVmMzM2NTc0YjUwNTc5MDFkOGViMzJmN2FkMmViODIzZTQyZjg1M2E2NjA2NGM5OAo", "Carpe diem", "9f3c0f2517201cc461de1758d5797e2d36cfee08b592d39b9eac6149c4ff8586a1a517b713dfc8264d42bd52d2a9026443cd9b8ef35889dbbd6bdbc0326f8e0f"},
        });
    }

    @DisplayName("Signing using a newly generated key")
    @ParameterizedTest(name = "Signing: {2}")
    @MethodSource("keyMessageSignature")
    public void testSign(String _unusedPrivateKey, String _unusedPublicKey, String message) {

        String signed = Hex.toHexString(new Signer().sign(message)); // MUT

        assertNotNull(signed);
        assertEquals(128, signed.length());
        //assertEquals(expected, signed);
    }

    @DisplayName("Verifying using various existing keys")
    @ParameterizedTest(name = "Verifying using key: {0}")
    @MethodSource("keyMessageSignature")
    public void testVerify(String privateKey, String publicKey, String message, String expected) {

        boolean verified = new Signer(privateKey, publicKey).verify(message, Hex.decode(expected)); // MUT

        assertTrue(verified);
    }

    @DisplayName("Signing using various existing keys")
    @ParameterizedTest(name = "Signing using key: {0}")
    @MethodSource("keysSignature")
    public void testSignUsingKeys(String privateKey, String publicKey, String expected) {

        String signed = Hex.toHexString(new Signer(privateKey, publicKey).sign("The quick brown fox jumps over the lazy dog")); // MUT

        assertNotNull(signed);
        assertEquals(128, signed.length());
        assertEquals(expected, signed);
    }

    @DisplayName("Verifying using various existing keys")
    @ParameterizedTest(name = "Verifying using key: {0}")
    @MethodSource("keysSignature")
    public void verifyUsingKeys(String privateKey, String publicKey, String expected) {

        boolean verified = new Signer(privateKey, publicKey).verify("The quick brown fox jumps over the lazy dog", Hex.decode(expected)); // MUT

        assertTrue(verified);
    }

    @DisplayName("Signing using key from a JKS")
    @ParameterizedTest(name = "Signing: {2}")
    @MethodSource("keyMessageSignature")
    public void testSignUsingJKS(String _unusedPrivateKey, String _unusedPublicKey, String message, String expected) throws UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {

        String signed = Hex.toHexString(new Signer(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias").sign(message)); // MUT

        assertNotNull(signed);
        assertEquals(128, signed.length());
        assertEquals(expected, signed);
    }


    @DisplayName("Signing using key from PEM files")
    @ParameterizedTest(name = "Signing: {2}")
    @MethodSource("keyMessageSignature")
    public void testSignUsingPemKeys(String _unusedPrivateKey, String _unusedPublicKey, String message, String expected) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        String signed = Hex.toHexString(new Signer(new File("src/test/data/private.pem"), new File("src/test/data/public.pem")).sign(message)); // MUT

        assertNotNull(signed);
        assertEquals(128, signed.length());
        assertEquals(expected, signed);
    }

    @DisplayName("Verifying using PEM keys")
    @ParameterizedTest(name = "Verifying signed message: {2}")
    @MethodSource("keyMessageSignature")
    public void verifyUsingPemKeys(String _privateKey, String _publicKey, String message, String expected) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        boolean verified = new Signer(new File("src/test/data/private.pem"), new File("src/test/data/public.pem")).verify(message, Hex.decode(expected)); // MUT

        assertTrue(verified);
    }

    @Test
    public void testThrowsInvalidKeySpecException() throws IOException {

        assertThrowsExactly(InvalidKeySpecException.class, () -> {
            new Signer(new File("src/test/data/public.pem"), new File("src/test/data/private.pem")); // keys swapped, both wrong
        });

        assertThrowsExactly(InvalidKeySpecException.class, () -> {
            new Signer(new File("src/test/data/private.pem"), new File("src/test/data/private.pem")); // wrong public key PEM file
        });

        assertThrowsExactly(InvalidKeySpecException.class, () -> {
            new Signer(new File("src/test/data/public.pem"), new File("src/test/data/public.pem")); // wrong private key PEM file
        });
    }
}