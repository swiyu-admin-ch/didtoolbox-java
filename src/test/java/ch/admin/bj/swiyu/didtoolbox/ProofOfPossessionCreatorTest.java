package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.WebVerifiableHistoryDidLogMetaPeeker;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("PMD")
class ProofOfPossessionCreatorTest extends AbstractUtilTestBase {
    private static final Duration ONE_DAY_LONG = Duration.ofDays(1);

    @Test
    void create_withValidParameters_returnsValidJWT() throws Exception {
        var nonce = "test_nonce";

        var didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);
        var didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog);

        var crypto = ProofOfPossessionJWSSigner.of(Path.of("src/test/data/assert-key-01"), didLogMeta.getDidDoc().getId() + "#my-assert-key-01");
        var proofCreator = new ProofOfPossessionCreator(crypto);

        var pop = proofCreator.create(nonce, ONE_DAY_LONG);

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
    void create_withInvalidSigner_throwsProofOfPossessionCreatorException() throws Exception {
        var exceptionMessage = "mock exception";
        var nonce = "my_nonce";
        var signer = mock(ProofOfPossessionJWSSigner.class);
        when(signer.getAlgorithm()).thenReturn(JWSAlgorithm.EdDSA);
        when(signer.getKid()).thenReturn(TEST_POP_JWS_KID);
        when(signer.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.EdDSA));
        when(signer.sign(any(), any())).thenThrow(new JOSEException(exceptionMessage));

        // create proof
        var creator = new ProofOfPossessionCreator(signer);
        var ex = assertThrowsExactly(ProofOfPossessionCreatorException.class, () -> creator.create(nonce, ONE_DAY_LONG));
        assertTrue(ex.getMessage().contains(exceptionMessage));
    }

    @Test
    void create_withoutDuration_throwsProofOfPossessionCreatorException() throws Exception {
        var nonce = "test_nonce";

        var didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);
        var didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog);

        var crypto = new EcP256ProofOfPossessionJWSSigner(Path.of("src/test/data/assert-key-01"), didLogMeta.getDidDoc().getId() + "#my-assert-key-01");
        var proofCreator = new ProofOfPossessionCreator(crypto);

        assertThrowsExactly(NullPointerException.class, () -> proofCreator.create(nonce, null));
    }

    @Test
    void create_withNonce_returnsJWTWithNullNonce() throws Exception {
        var didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);
        var didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog);

        var crypto = new EcP256ProofOfPossessionJWSSigner(Path.of("src/test/data/assert-key-01"), didLogMeta.getDidDoc().getId() + "#my-assert-key-01");
        var proofCreator = new ProofOfPossessionCreator(crypto);

        var pop = proofCreator.create(null, ONE_DAY_LONG);

        var header = pop.getHeader();
        assertEquals(JWSAlgorithm.ES256, pop.getHeader().getAlgorithm());
        assertTrue(didLog.contains(header.getKeyID()));

        var payload = pop.getPayload().toJSONObject();
        assertNull(payload.get("nonce"));
    }
}
