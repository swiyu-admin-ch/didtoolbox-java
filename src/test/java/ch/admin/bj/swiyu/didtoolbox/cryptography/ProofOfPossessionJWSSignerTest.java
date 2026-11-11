package ch.admin.bj.swiyu.didtoolbox.cryptography;

import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreLoader;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.security.KeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProofOfPossessionJWSSignerTest {

    private static final String KID = "did:webvh:scid:example.com#kid";
    private static final String ALIAS = "my-alias";

    @Test
    void of_validP256Pem_returnsJWSSigner() {
       var path = Path.of("src/test/data/assert-key-01");
       var signer = assertDoesNotThrow(() -> ProofOfPossessionJWSSigner.of(path, KID));

       assertEquals(JWSAlgorithm.ES256, signer.getAlgorithm());
       assertEquals(KID, signer.getKid());
       assertNotNull(signer.getJCAContext());

       var data = "Hello, world!".getBytes();
       var header = new JWSHeader(JWSAlgorithm.ES256);
       assertDoesNotThrow(() -> signer.sign(header, data));
    }

    @Test
    void of_validEd25519Pem_returnsJWSSigner() {
        var path = Path.of("src/test/data/private.pem");
        var signer = assertDoesNotThrow(() -> ProofOfPossessionJWSSigner.of(path, KID));

        assertEquals(JWSAlgorithm.EdDSA, signer.getAlgorithm());
        assertEquals(KID, signer.getKid());
        assertNotNull(signer.getJCAContext());

        var data = "Hello, world!".getBytes();
        var header = new JWSHeader(JWSAlgorithm.EdDSA);
        assertDoesNotThrow(() -> signer.sign(header, data));
    }

    @Test
    void of_invalidPemFile_returnsJWSSigner() {
        var path = Path.of("src/test/data/README.md");
        assertThrowsExactly(VcDataIntegrityCryptographicSuiteException.class, () -> ProofOfPossessionJWSSigner.of(path, KID));
    }

    @Test
    void of_primusWithP256Key_returnsSignerProducingVerifiableES256Signature() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var keyPair = generator.generateKeyPair();
        var password = "secret".toCharArray();

        var keyStore = mock(KeyStore.class);
        when(keyStore.getProvider()).thenReturn(generator.getProvider());
        var primus = mock(PrimusKeyStoreLoader.class);
        when(primus.loadKeyPair(ALIAS, password)).thenReturn(keyPair);
        when(primus.getKeyStore()).thenReturn(keyStore);

        var signer = ProofOfPossessionJWSSigner.of(primus, ALIAS, password, KID);

        assertEquals(JWSAlgorithm.ES256, signer.getAlgorithm());
        assertEquals(KID, signer.getKid());
        assertSame(generator.getProvider(), signer.getJCAContext().getProvider());

        var jws = new JWSObject(new JWSHeader.Builder(signer.getAlgorithm()).keyID(signer.getKid()).build(), new Payload("Hello, world!"));
        jws.sign(signer);
        assertTrue(JWSObject.parse(jws.serialize()).verify(new ECDSAVerifier((ECPublicKey) keyPair.getPublic())));
    }

    @Test
    void of_primusLoadKeyPairThrowsKeyException_propagatesUnchanged() throws Exception {
        var keyException = new KeyException("no such key");
        var primus = mock(PrimusKeyStoreLoader.class);
        when(primus.loadKeyPair(ALIAS, null)).thenThrow(keyException);

        var thrown = assertThrowsExactly(KeyException.class, () -> ProofOfPossessionJWSSigner.of(primus, ALIAS, null, KID));

        assertSame(keyException, thrown);
    }
}
