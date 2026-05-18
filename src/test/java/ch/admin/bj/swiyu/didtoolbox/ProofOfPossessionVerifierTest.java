package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.WebVerifiableHistoryDidLogMetaPeeker;
import ch.admin.eid.did_sidekicks.DidDoc;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("PMD")
class ProofOfPossessionVerifierTest extends AbstractUtilTestBase {
    private static final Duration ONE_DAY_LONG = Duration.ofDays(1);

    String didLog;
    DidDoc didDoc;
    ProofOfPossessionJWSSigner signer;

    @BeforeEach
    void setUp() {
        didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);
        var didLogMeta = assertDoesNotThrow(() -> WebVerifiableHistoryDidLogMetaPeeker.peek(didLog));
        didDoc = didLogMeta.getDidDoc();
        signer = assertDoesNotThrow(() -> new EcP256ProofOfPossessionJWSSigner(Path.of("src/test/data/assert-key-01"), didLogMeta.getDidDoc().getId() + "#my-assert-key-01"));
    }

    @Test
    void testProofOfPossessionConstructor() {
        assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> new ProofOfPossessionVerifier("invalid did log"));
        assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));
        assertDoesNotThrow(() -> new ProofOfPossessionVerifier(buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE)));
    }

    @Test
    void testVerify() {
        var nonce = "my_nonce";

        // create proof
        var proof = assertDoesNotThrow(() -> new ProofOfPossessionCreator(signer).create(nonce, ONE_DAY_LONG));

        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));
        assertTrue(verifier.isValid(proof, nonce));

        assertDoesNotThrow(() -> verifier.verify(proof, nonce));
    }

    @Test
    void verify_KeyNotInDidLog() {
        var nonce = "my_nonce";
        signer = assertDoesNotThrow(() -> new EcP256ProofOfPossessionJWSSigner(Path.of("src/test/data/assert-key-01"), didDoc.getId() + "#my-assert-key-01-not-in-doc"));
        var proof = assertDoesNotThrow(() -> new ProofOfPossessionCreator(signer).create(nonce, ONE_DAY_LONG));

        // for the purpose, you may also use EXAMPLE_POP_JWS_SIGNER_ANOTHER here, instead
        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog)); // CAUTION: Using a whole other key

        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(proof, nonce));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.KEY_MISMATCH, exc.getErrorCause());
    }

    @Test
    void verify_expired_thenFailure() {
        var expiredJWT = assertDoesNotThrow(() -> SignedJWT.parse("eyJraWQiOiJkaWQ6d2Vidmg6UW1TbXJ0dVJMYm44R0JxeGIzekdiZlNpdFc0dUFYeVBWalhlVUJtcXJjS01iMTppZGVudGlmaWVyLXJlZy50cnVzdC1pbmZyYS5zd2l5dS1pbnQuYWRtaW4uY2g6YXBpOnYxOmRpZDoxOGZhN2M3Ny05ZGQxLTRlMjAtYTE0Ny1mYjFiZWMxNDYwODUjbXktYXNzZXJ0LWtleS0wMSIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJkaWQ6d2Vidmg6UW1TbXJ0dVJMYm44R0JxeGIzekdiZlNpdFc0dUFYeVBWalhlVUJtcXJjS01iMTppZGVudGlmaWVyLXJlZy50cnVzdC1pbmZyYS5zd2l5dS1pbnQuYWRtaW4uY2g6YXBpOnYxOmRpZDoxOGZhN2M3Ny05ZGQxLTRlMjAtYTE0Ny1mYjFiZWMxNDYwODUiLCJleHAiOjE3NzkxNzkyMzAsIm5vbmNlIjoibXlfbm9uY2UiLCJpYXQiOjE3NzkwOTI4MzB9.QZwCyPGcwHUJWUL_AJNaKRf_XJSZmJ1fVZx5L1yJwAY7meiLV4UIu-oHvcHQXz1FhFC003PCdAC07UgiAK66Ng"));
        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE)));
        var e = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(expiredJWT, "my_nonce"));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.EXPIRED, e.getErrorCause());
    }

    @Test
    void verify_nonceMismatch_thenFailure() {
        var nonce = "bar";

        // create proof
        var proof = assertDoesNotThrow(() -> new ProofOfPossessionCreator(signer).create(nonce, ONE_DAY_LONG));
        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));

        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(proof, "foo"));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.INVALID_NONCE, exc.getErrorCause());
    }

    @Test
    void verify_unsupportedAlgorithm_thenFailure() {
        // JWT placeholder from https://www.jwt.io/ using HS256
        var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
        var signedJWT = assertDoesNotThrow(() -> SignedJWT.parse(jwt));
        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));

        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(signedJWT, "foo"));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.UNSUPPORTED_ALGORITHM, exc.getErrorCause());
    }
}
