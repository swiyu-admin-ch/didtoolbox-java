package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didtoolbox.TrustDidWeb;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

public class ProofOfPossessionCreatorTest extends AbstractUtilTestBase {
    private static final Duration duration = Duration.ofDays(1);

    @Test
    void testProofOfPossessionCreateValidJWT() throws Exception {
        var nonce = "HelloWorld";

        var didLog = buildInitialDidLogEntry(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER);
        var didTdw = DidLogMetaPeeker.peek(didLog).didDocId;
        var didWeb = TrustDidWeb.Companion.read(didTdw, didLog);

        // create proof
        var proof = new ProofOfPossessionCreator(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER, didWeb).create(nonce, duration);

        // verify proof
        assert(proof.getHeader().getAlgorithm().equals(JWSAlgorithm.Ed25519));
        assert(didLog.contains(proof.getHeader().getKeyID()));
        assert(proof.getPayload().toJSONObject().get("nonce").toString().equals(nonce));

        var isValid = new ProofOfPossessionVerifier(didWeb).isValid(proof, nonce);
        assert(isValid);
    }

    @Test
    void testProofOfPossessionCreateInvalidDidLog() {
        assertThrows(Exception.class, () -> new ProofOfPossessionCreator(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER, ""));
    }
}
