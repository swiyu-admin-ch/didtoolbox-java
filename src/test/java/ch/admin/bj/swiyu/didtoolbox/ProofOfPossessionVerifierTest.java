
package ch.admin.bj.swiyu.didtoolbox;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class ProofOfPossessionVerifierTest extends AbstractUtilTestBase {
    private static final Duration ONE_DAY_LONG = Duration.ofDays(1);

    @Test
    void testVerify() {
        var nonce = "my_nonce";

        // create proof
        AtomicReference<SignedJWT> proof = new AtomicReference<>();
        assertDoesNotThrow(() ->
                proof.set(new ProofOfPossessionCreator(TEST_POP_JWS_SIGNER)
                        .create(nonce, ONE_DAY_LONG))
        );

        AtomicReference<ProofOfPossessionVerifier> verifier = new AtomicReference<>();
        assertDoesNotThrow(() ->
                // for the purpose, you may also use EXAMPLE_POP_JWS_SIGNER here, instead
                verifier.set(new ProofOfPossessionVerifier(
                        buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER)))
        );

        assertTrue(verifier.get().isValid(proof.get(), nonce));

        assertDoesNotThrow(() ->
                verifier.get().verify(proof.get(), nonce)
        );
    }

    @Test
    void testVerifyKeyMismatch() {
        var nonce = "my_nonce";

        // create proof
        AtomicReference<SignedJWT> proof = new AtomicReference<>();
        assertDoesNotThrow(() ->
                proof.set(new ProofOfPossessionCreator(TEST_POP_JWS_SIGNER)
                        .create(nonce, ONE_DAY_LONG))
        );

        AtomicReference<ProofOfPossessionVerifier> verifier = new AtomicReference<>();
        assertDoesNotThrow(() ->
                // for the purpose, you may also use EXAMPLE_POP_JWS_SIGNER_ANOTHER here, instead
                verifier.set(new ProofOfPossessionVerifier(
                        buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER))) // CAUTION: Using a whole other key
        );

        ProofOfPossessionVerifier finalVerifier = verifier.get();
        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () ->
                finalVerifier.verify(proof.get(), nonce)
        );
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.KeyMismatch, exc.getErrorCause());
    }

    @Test
    void testVerifyKeyIdMismatch() {
        var nonce = "my_nonce";

        var publicKeyMultibase = Ed25519Utils.encodeMultibase(TEST_PUBLIC_KEY_ANOTHER); // CAUTION: Using a whole other key
        var signedJWT = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.Ed25519)
                        .keyID("did:key:" + publicKeyMultibase + "#" + publicKeyMultibase)
                        .build(),
                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                        .claim("nonce", nonce)
                        .expirationTime(java.util.Date.from(java.time.ZonedDateTime.now().plusDays(1).toInstant()))
                        .build());
        // gets signed with another key (having different keyID than those on the base of PUBLIC_KEY_ANOTHER)
        try {
            signedJWT.sign(TEST_POP_JWS_SIGNER);
        } catch (JOSEException e) {
            fail(e);
        }

        AtomicReference<ProofOfPossessionVerifier> verifier = new AtomicReference<>();
        assertDoesNotThrow(() ->
                // for the purpose, you may also use EXAMPLE_POP_JWS_SIGNER here, instead
                verifier.set(new ProofOfPossessionVerifier(
                        buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER)))
        );

        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.get().verify(signedJWT, nonce));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.KeyMismatch, exc.getErrorCause());
    }

    @Test
    void testVerifyExpired() {

        AtomicReference<SignedJWT> expiredJWT = new AtomicReference<>();
        assertDoesNotThrow(() ->
                expiredJWT.set(SignedJWT.parse("eyJraWQiOiJkaWQ6a2V5Ono2TWt0ZEFyM2lVUmVVN0hzQ2Y3Sm5vQ2pRNXVycEtUeFpTQzQ5S25qRVZzQTVDQSN6Nk1rdGRBcjNpVVJlVTdIc0NmN0pub0NqUTV1cnBLVHhaU0M0OUtuakVWc0E1Q0EiLCJhbGciOiJFZDI1NTE5In0.eyJleHAiOjE3NTM4NzE5OTAsIm5vbmNlIjoiZm9vIn0.Srooog6HXT8TPReDjkhkvGAwwcqe7MgMDbbOWgqfxo2qs1zrug-DJQPv7_lpTOnJmQpvkO7I_-y9d37QBaC-Cw"))
        );

        try {
            // for the purpose, you may also use EXAMPLE_POP_JWS_SIGNER here, instead
            var verifier = new ProofOfPossessionVerifier(buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER));
            verifier.verify(expiredJWT.get(), "foo");
            fail();
        } catch (ProofOfPossessionVerifierException e) {
            assertEquals(ProofOfPossessionVerifierException.ErrorCause.Expired, e.getErrorCause());
        }
    }

    @Test
    void testVerifyNonceMismatch() {
        var nonce = "bar";

        // create proof
        AtomicReference<SignedJWT> proof = new AtomicReference<>();
        assertDoesNotThrow(() ->
                proof.set(new ProofOfPossessionCreator(TEST_POP_JWS_SIGNER)
                        .create(nonce, Duration.ofDays(1)))
        );

        AtomicReference<ProofOfPossessionVerifier> verifier = new AtomicReference<>();
        assertDoesNotThrow(() ->
                // for the purpose, you may also use EXAMPLE_POP_JWS_SIGNER here, instead
                verifier.set(new ProofOfPossessionVerifier(
                        buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER)))
        );

        ProofOfPossessionVerifier finalVerifier = verifier.get();
        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () ->
                finalVerifier.verify(proof.get(), "foo"));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.InvalidNonce, exc.getErrorCause());
    }

    @Test
    void testVerifyUnsupportedAlgorithm() {
        // JWT placeholder from https://www.jwt.io/ using HS256
        var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
        AtomicReference<SignedJWT> signedJWT = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            signedJWT.set(SignedJWT.parse(jwt));
        });

        AtomicReference<ProofOfPossessionVerifier> verifier = new AtomicReference<>();
        assertDoesNotThrow(() ->
                // for the purpose, you may also use EXAMPLE_POP_JWS_SIGNER here, instead
                verifier.set(new ProofOfPossessionVerifier(
                        buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER)))
        );

        ProofOfPossessionVerifier finalVerifier = verifier.get();
        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () ->
                finalVerifier.verify(signedJWT.get(), "foo"));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.UnsupportedAlgorithm, exc.getErrorCause());
    }
}
