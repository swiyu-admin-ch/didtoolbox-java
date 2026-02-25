package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.WebVerifiableHistoryDidLogMetaPeeker;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("PMD")
class ProofOfPossessionCreatorTest extends AbstractUtilTestBase {
    private static final Duration ONE_DAY_LONG = Duration.ofDays(1);

    @Test
    void testCreateJWT_valid() throws Exception {
        var nonce = "test_nonce";

        var didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);
        var didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog);

        var crypto = new EcP256ProofOfPossessionJWSSigner(Path.of("src/test/data/assert-key-01"), didLogMeta.getDidDoc().getId() + "#my-assert-key-01");
        var proofCreator = new ProofOfPossessionCreator(crypto);

        var pop = proofCreator.create(nonce, Duration.ofDays(90));

        var header = pop.getHeader();
        assertEquals(JWSAlgorithm.ES256, pop.getHeader().getAlgorithm());
        assertTrue(didLog.contains(header.getKeyID()));

        var payload = pop.getPayload().toJSONObject();
        assertNotNull(payload.get("exp"));
        assertNotNull(payload.get("iat"));
        assertNotNull(payload.get("iss"));
        assertEquals(payload.get("iss"), didLogMeta.getDidDoc().getId());
        assertNotNull(payload.get("nonce"));
        assertEquals(nonce, payload.get("nonce").toString());

        // verify proof
        assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog).isValid(pop, nonce));
    }

    @Test
    void testCreateInvalid() throws Exception {
        var nonce = "my_nonce";

        // NOTE The very same keys are shared only between:
        //      - EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER         and EXAMPLE_POP_JWS_SIGNER
        //      - EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER and EXAMPLE_POP_JWS_SIGNER_ANOTHER

        // for the purpose, you may also use EXAMPLE_POP_JWS_SIGNER_ANOTHER here, instead
        var didLog = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE_ANOTHER);

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

    @Test
    void testCreateValidJWT_fail() throws Exception {
        var nonce = "my_nonce";

        var didLog = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE);

        // create proof
        var proof = new ProofOfPossessionCreator(TEST_POP_JWS_SIGNER)
                .create(nonce, ONE_DAY_LONG);

        // verify JWT (head/payload) claims
        var header = proof.getHeader();
        assertEquals(JWSAlgorithm.Ed25519, header.getAlgorithm());
        assertFalse(didLog.contains(header.getKeyID()));
        var payload = proof.getPayload().toJSONObject();
        assertNotNull(payload.get("exp"));
        assertNotNull(payload.get("nonce"));
        assertEquals(nonce, payload.get("nonce").toString());

        // verify proof
        assertFalse(new ProofOfPossessionVerifier(didLog).isValid(proof, nonce));
    }
}
