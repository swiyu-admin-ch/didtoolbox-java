
package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didtoolbox.TrustDidWeb;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

public class ProofOfPossessionVerifierTest extends AbstractUtilTestBase {
    private static final Duration duration = Duration.ofDays(1);

    @Test
    void testVerifyProofOfPossessionKeysNotMatching() throws Exception {
        var nonce = "HelloWorld";

        var didLog = buildInitialDidLogEntry(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER);

        // create proof
        var jwt = new ProofOfPossessionCreator(VERIFICATION_METHOD_KEY_PROVIDER_JKS, didLog).create(nonce, duration);
        var verifier = new ProofOfPossessionVerifier(didLog);
        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(jwt, nonce));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.InvalidSignature, exc.getErrorCause());
    }

    @Test
    void testVerifyProofOfPossessionExpired() throws Exception {
        var expiredJWT = SignedJWT.parse("eyJraWQiOiJkaWQ6a2V5Ono2TWt0ZEFyM2lVUmVVN0hzQ2Y3Sm5vQ2pRNXVycEtUeFpTQzQ5S25qRVZzQTVDQSN6Nk1rdGRBcjNpVVJlVTdIc0NmN0pub0NqUTV1cnBLVHhaU0M0OUtuakVWc0E1Q0EiLCJhbGciOiJFZDI1NTE5In0.eyJleHAiOjE3NTM4NzE5OTAsIm5vbmNlIjoiZm9vIn0.Srooog6HXT8TPReDjkhkvGAwwcqe7MgMDbbOWgqfxo2qs1zrug-DJQPv7_lpTOnJmQpvkO7I_-y9d37QBaC-Cw");
        try {
            TrustDidWeb didWeb = null;
            var verifier = new ProofOfPossessionVerifier(didWeb);
            verifier.verify(expiredJWT, "foo");
            assert (false);
        } catch (ProofOfPossessionVerifierException e) {
            assertEquals(ProofOfPossessionVerifierException.ErrorCause.Expired, e.getErrorCause());
        }
    }

    @Test
    void testVerifyProofOfPossessionNonceNotMatching() throws Exception {
        var nonce = "bar";

        var didLog = buildInitialDidLogEntry(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER);

        // create proof
        var proof = new ProofOfPossessionCreator(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER, didLog).create(nonce, duration);

        var verifier = new ProofOfPossessionVerifier(didLog);
        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(proof, "foo"));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.InvalidNonce, exc.getErrorCause());
    }

    @Test
    void testVerifyProofOfPossessionKeyNotFoundInDID() throws Exception {
        var nonce = "bar";
        var didLog = buildInitialDidLogEntry(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER);

        var publicKeyMultibase = ch.admin.bj.swiyu.didtoolbox.Ed25519Utils.encodeMultibase(PUBLIC_KEY);
        var keyID = "did:key:" + publicKeyMultibase + "#" + publicKeyMultibase;
        var signedJWT = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.Ed25519)
                        .keyID(keyID)
                        .build(),
                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                        .claim("nonce", nonce)
                        .expirationTime(java.util.Date.from(java.time.ZonedDateTime.now().plusDays(1).toInstant()))
                        .build());
        signedJWT.sign(VERIFICATION_METHOD_KEY_PROVIDER_JKS);

        var verifier = new ProofOfPossessionVerifier(didLog);
        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(signedJWT, nonce));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.KeyNotFoundInDID, exc.getErrorCause());
    }

    @Test
    void testVerifyProofOfPossessionUnsupportedAlgorithm() throws Exception {
        // JWT placeholder from https://www.jwt.io/ using HS256
        var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
        var signedJWT = SignedJWT.parse(jwt);


        TrustDidWeb didWeb = null;
        var verifier = new ProofOfPossessionVerifier(didWeb);
        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(signedJWT, "foo"));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.UnsupportedAlgorithm, exc.getErrorCause());
    }
}
