package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ProofOfPossessionJWSSignerTest {

    private static final String KID = "did:webvh:scid:example.com#kid";

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
}
