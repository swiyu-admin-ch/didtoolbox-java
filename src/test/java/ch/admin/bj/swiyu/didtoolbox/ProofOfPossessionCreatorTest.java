package ch.admin.bj.swiyu.didtoolbox;

import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

public class ProofOfPossessionCreatorTest extends AbstractUtilTestBase {
    private static final Duration ONE_DAY_LONG = Duration.ofDays(1);

    @Test
    void testCreateValidJWT() throws Exception {
        var nonce = "my_nonce";

        var didLog = buildInitialTdwDidLogEntry(TEST_POP_JWS_SIGNER);

        // create proof
        var proof = new ProofOfPossessionCreator(TEST_POP_JWS_SIGNER)
                .create(nonce, ONE_DAY_LONG);

        // verify JWT (head/payload) claims
        var header = proof.getHeader();
        assertEquals(JWSAlgorithm.Ed25519, header.getAlgorithm());
        assertTrue(didLog.contains(header.getKeyID()));
        var payload = proof.getPayload().toJSONObject();
        assertNotNull(payload.get("exp"));
        assertNotNull(payload.get("nonce"));
        assertEquals(nonce, payload.get("nonce").toString());

        // verify proof
        assertTrue(new ProofOfPossessionVerifier(didLog).isValid(proof, nonce));
    }

    @Test
    void testCreateInvalid() throws Exception {
        var nonce = "my_nonce";

        // NOTE The very same keys are shared only between:
        //      - EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER         and EXAMPLE_POP_JWS_SIGNER
        //      - EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER and EXAMPLE_POP_JWS_SIGNER_ANOTHER

        // for the purpose, you may also use EXAMPLE_POP_JWS_SIGNER_ANOTHER here, instead
        var didLog = buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER);

        // create proof
        var proof = new ProofOfPossessionCreator(TEST_POP_JWS_SIGNER)
                .create(nonce, ONE_DAY_LONG);

        // verify JWT (head/payload) claims
        var header = proof.getHeader();
        assertEquals(JWSAlgorithm.Ed25519, header.getAlgorithm());

        // CAUTION: MUST differ!
        assertFalse(didLog.contains(header.getKeyID()));

        var payload = proof.getPayload().toJSONObject();
        assertNotNull(payload.get("exp"));
        assertNotNull(payload.get("nonce"));
        assertEquals(nonce, payload.get("nonce").toString());

        // CAUTION: MUST be invalid
        assertFalse(new ProofOfPossessionVerifier(didLog).isValid(proof, nonce));
    }
}
