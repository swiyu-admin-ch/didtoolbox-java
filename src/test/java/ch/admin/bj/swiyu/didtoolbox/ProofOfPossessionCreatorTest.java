package ch.admin.bj.swiyu.didtoolbox;

import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

public class ProofOfPossessionCreatorTest extends AbstractUtilTestBase {
    private static final Duration ONE_DAY_LONG = Duration.ofDays(1);

    @Test
    void testCreateValidJWT() throws Exception {
        var nonce = "HelloWorld";

        var didLog = buildInitialDidLogEntry(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER);

        // create proof
        var proof = new ProofOfPossessionCreator(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER)
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
}
