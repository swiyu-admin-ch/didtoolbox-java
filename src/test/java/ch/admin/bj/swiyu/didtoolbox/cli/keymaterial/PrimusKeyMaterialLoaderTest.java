package ch.admin.bj.swiyu.didtoolbox.cli.keymaterial;

import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusEd25519VerificationMethodKeyProviderImpl;
import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreLoader;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class PrimusKeyMaterialLoaderTest {

    private static final String ALIAS = "my-alias";
    private static final String KID = "my-kid";
    private static final String PASSWORD = "secret";
    private static final char[] BLANKED_PASSWORD = " ".repeat(PASSWORD.length()).toCharArray();

    private final PrimusKeyStoreLoader primus = mock(PrimusKeyStoreLoader.class);
    private final PrimusKeyMaterialLoader loader = new PrimusKeyMaterialLoader(primus, ALIAS, PASSWORD);

    // The very array handed over gets blanked afterwards, so only a copy tells what the key store loader actually received
    private char[] passwordAtCall;

    private void whenLoadingKeyPair(Callable<KeyPair> outcome) throws GeneralSecurityException {
        when(primus.loadKeyPair(eq(ALIAS), any())).thenAnswer(invocation -> {
            passwordAtCall = ((char[]) invocation.getArgument(1)).clone();
            return outcome.call();
        });
    }

    private void assertPasswordHandedOverThenBlanked() throws GeneralSecurityException {
        var handedOver = ArgumentCaptor.forClass(char[].class);
        verify(primus).loadKeyPair(eq(ALIAS), handedOver.capture());
        assertArrayEquals(PASSWORD.toCharArray(), passwordAtCall);
        assertArrayEquals(BLANKED_PASSWORD, handedOver.getValue());
    }

    private static KeyPair p256KeyPair() throws GeneralSecurityException {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static Stream<Exception> wrappedKeyLoadingFailures() {
        return Stream.of(new KeyStoreException("keystore not loaded"), new KeyException("no such alias"));
    }

    @Test
    void loadCryptographicSuite_nullPassword_handsNullOver() throws Exception {
        when(primus.loadKeyPair(ALIAS, null)).thenThrow(new KeyException("no such alias"));
        var loaderWithoutPassword = new PrimusKeyMaterialLoader(primus, ALIAS, null);

        assertThrowsExactly(VcDataIntegrityCryptographicSuiteException.class, loaderWithoutPassword::loadCryptographicSuite); // MUT

        verify(primus).loadKeyPair(ALIAS, null);
    }

    @Test
    void loadProofOfPossessionSigner_nullPassword_handsNullOver() throws Exception {
        when(primus.loadKeyPair(ALIAS, null)).thenReturn(p256KeyPair());
        when(primus.getKeyStore()).thenReturn(KeyStore.getInstance("PKCS12"));

        var signer = new PrimusKeyMaterialLoader(primus, ALIAS, null).loadProofOfPossessionSigner(KID); // MUT

        assertEquals(KID, signer.getKid());
        verify(primus).loadKeyPair(ALIAS, null);
    }

    @Test
    void loadCryptographicSuite_success_blanksPassword() throws Exception {
        // CAUTION The real constructor cannot succeed here, as its sanity check signs via the (unavailable) Primus JCE provider
        var handedOver = new AtomicReference<char[]>();
        try (var constructions = mockConstruction(PrimusEd25519VerificationMethodKeyProviderImpl.class, (mock, context) -> {
            handedOver.set((char[]) context.arguments().get(2));
            passwordAtCall = handedOver.get().clone();
        })) {
            var cryptoSuite = loader.loadCryptographicSuite(); // MUT

            assertSame(constructions.constructed().getFirst(), cryptoSuite);
        }

        assertArrayEquals(PASSWORD.toCharArray(), passwordAtCall);
        assertArrayEquals(BLANKED_PASSWORD, handedOver.get());
    }

    @ParameterizedTest(name = "For cause: {0}")
    @MethodSource("wrappedKeyLoadingFailures")
    void loadCryptographicSuite_keyLoadingFails_wrapsCauseAndBlanksPassword(Exception cause) throws Exception {
        whenLoadingKeyPair(() -> {
            throw cause;
        });

        var exc = assertThrowsExactly(VcDataIntegrityCryptographicSuiteException.class, loader::loadCryptographicSuite); // MUT

        assertSame(cause, exc.getCause());
        assertPasswordHandedOverThenBlanked();
    }

    @Test
    void loadProofOfPossessionSigner_success_blanksPassword() throws Exception {
        var keyPair = p256KeyPair();
        whenLoadingKeyPair(() -> keyPair);
        when(primus.getKeyStore()).thenReturn(KeyStore.getInstance("PKCS12"));

        var signer = loader.loadProofOfPossessionSigner(KID); // MUT

        assertEquals(KID, signer.getKid());
        assertEquals(JWSAlgorithm.ES256, signer.getAlgorithm());
        assertPasswordHandedOverThenBlanked();
    }

    @Test
    void loadProofOfPossessionSigner_keyLoadingFails_propagatesUnwrappedAndBlanksPassword() throws Exception {
        var cause = new UnrecoverableKeyException("wrong password");
        whenLoadingKeyPair(() -> {
            throw cause;
        });

        var exc = assertThrowsExactly(UnrecoverableKeyException.class, () -> loader.loadProofOfPossessionSigner(KID)); // MUT

        assertSame(cause, exc);
        assertPasswordHandedOverThenBlanked();
    }
}
