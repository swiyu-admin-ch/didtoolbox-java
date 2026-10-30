package ch.admin.bj.swiyu.didtoolbox.pop;

import ch.admin.bj.swiyu.didtoolbox.cryptography.EcP256ProofOfPossessionJWSSigner;
import ch.admin.bj.swiyu.didtoolbox.cryptography.ProofOfPossessionJWSSigner;
import ch.admin.bj.swiyu.didtoolbox.did.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryDidLogMetaPeeker;
import ch.admin.eid.did_sidekicks.DidDoc;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.text.ParseException;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("PMD")
class ProofOfPossessionVerifierTest extends AbstractUtilTestBase {
    private static final String NONCE = "example_nonce";
    private static final Duration ONE_DAY_LONG = Duration.ofDays(1);

    // Hardcoded didLog to ensure kid does not change between runs
    String didLog = """
            {"versionId":"1-QmSck9HJS4CJfnPZQW496L12E48Js81cYfk9EVDoyKZLEY","versionTime":"2012-12-12T12:12:12Z","parameters":{"method":"did:webvh:1.0","scid":"QmcKVwjN7y5H8yZQYDacYyju29nhVaeyxT5Q8BVt3Wfdso","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"],"portable":false},"state":{"id":"did:webvh:QmcKVwjN7y5H8yZQYDacYyju29nhVaeyxT5Q8BVt3Wfdso:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","profile_version":"swiss-profile-anchor:1.0.0","authentication":["did:webvh:QmcKVwjN7y5H8yZQYDacYyju29nhVaeyxT5Q8BVt3Wfdso:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:webvh:QmcKVwjN7y5H8yZQYDacYyju29nhVaeyxT5Q8BVt3Wfdso:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmcKVwjN7y5H8yZQYDacYyju29nhVaeyxT5Q8BVt3Wfdso:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","controller":"did:webvh:QmcKVwjN7y5H8yZQYDacYyju29nhVaeyxT5Q8BVt3Wfdso:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:webvh:QmcKVwjN7y5H8yZQYDacYyju29nhVaeyxT5Q8BVt3Wfdso:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","controller":"did:webvh:QmcKVwjN7y5H8yZQYDacYyju29nhVaeyxT5Q8BVt3Wfdso:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","proofPurpose":"assertionMethod","proofValue":"z3G6yaJW1yMsfRgN1HKAHXtWRHVCZksTsDGL5KjU8rQTQ174waaatGcz3sVH7JMnBF4wYU9t6QexRuDEmQ2yXXoFE"}]}
            """;
    DidDoc didDoc;
    ProofOfPossessionJWSSigner signer;
    ProofOfPossessionVerifier verifier;

    @BeforeEach
    void setUp() {
        var didLogMeta = assertDoesNotThrow(() -> WebVerifiableHistoryDidLogMetaPeeker.peek(didLog));
        didDoc = didLogMeta.getDidDoc();
        signer = assertDoesNotThrow(() -> new EcP256ProofOfPossessionJWSSigner(Path.of("src/test/data/assert-key-01"), didLogMeta.getDidDoc().getId() + "#my-assert-key-01"));
        verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));
    }

    @Test
    void testProofOfPossessionConstructor() {
        assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> new ProofOfPossessionVerifier("invalid did log"));
        assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));
        assertDoesNotThrow(() -> new ProofOfPossessionVerifier(buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE)));
    }

    @Test
    void isValid_withCreatorCreatedPoP_returnsTrue() {
        // create proof
        var proof = assertDoesNotThrow(() -> new ProofOfPossessionCreator(signer).create(NONCE, ONE_DAY_LONG));

        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));
        assertTrue(verifier.isValid(proof, NONCE));
    }

    @Test
    void verify_withP256Key_doesNotThrow() {
        // create proof
        var proof = assertDoesNotThrow(() -> new ProofOfPossessionCreator(signer).create(NONCE, ONE_DAY_LONG));

        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));
        assertDoesNotThrow(() -> verifier.verify(proof, NONCE));
    }

    @Test
    void verify_withEd25519Key_doesNotThrow() {
        var didLog = """
                {"versionId":"1-QmPuz69mEWiTum1PCzmu5zUgdG4vCKWi4FkBZTnMvGYHSa","versionTime":"2026-07-22T07:18:47Z","parameters":{"method":"did:webvh:1.0","scid":"QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP","updateKeys":["z6Mks5QkVWEK4w1GirvtzWpCkXUMoeiCEgTLdmuPTwpzxmLi"],"portable":false},"state":{"id":"did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com","profile_version":"swiss-profile-anchor:1.0.0","authentication":["did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com#auth-key-01","did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com#auth-key-02"],"assertionMethod":["did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com#assert-key-01","did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com#assert-key-02"],"verificationMethod":[{"id":"did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com#auth-key-01","controller":"did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"OfyYdxv2AjSTMddJHONMFHnXLcZnPiQ1KGFa-AX75x0","kid":"auth-key-01"}},{"id":"did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com#auth-key-02","controller":"did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"auth-key-02","x":"CCw9szn4CYfHmTKluoERTU40QOX68ghbxQWz7HUsjuI","y":"6Bf9ySbmakgFx-aApAN2okcvZ-nqW-HvARS_mQd9010"}},{"id":"did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com#assert-key-01","controller":"did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"-BfbOxS0VRGntlDa8TmcoXfEZP_EvpgKox67sARrlsE","kid":"assert-key-01"}},{"id":"did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com#assert-key-02","controller":"did:webvh:QmSDKjwjKxjf9Bie8F6V9Up9j6LUtv8TRawKVP64dVQXdP:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"assert-key-02","x":"arXHklzxgekECtQ9QwTfEuCVMrJSdCte7KUWFrKQ8kI","y":"0NS2Z8ydCXU7IJoM86shegENExHgLGPfPx3Yi9YK9kM"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-07-22T07:18:47Z","verificationMethod":"did:key:z6Mks5QkVWEK4w1GirvtzWpCkXUMoeiCEgTLdmuPTwpzxmLi#z6Mks5QkVWEK4w1GirvtzWpCkXUMoeiCEgTLdmuPTwpzxmLi","proofPurpose":"assertionMethod","proofValue":"z53mYjrN7WBdPoxp8LBCMbm7koYAqGCkEJQiu6TqjUTKk8x8oGGcM9PWSUX3mDzXAEuzjjhEFpEcCb4TwjCt6eqRf"}]}
                """;
        var jwt = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJ2aDpRbVNES2p3akt4amY5QmllOEY2VjlVcDlqNkxVdHY4VFJhd0tWUDY0ZFZRWGRQOmV4YW1wbGUuY29tI2F1dGgta2V5LTAxIiwidHlwIjoiSldUIn0.eyJpc3MiOiJkaWQ6d2Vidmg6UW1TREtqd2pLeGpmOUJpZThGNlY5VXA5ajZMVXR2OFRSYXdLVlA2NGRWUVhkUDpleGFtcGxlLmNvbSIsImV4cCI6MTAwMDAwMDAwMDAsIm5vbmNlIjoibXlfbm9uY2UiLCJpYXQiOjE3ODQ3MDQ2Mjh9.eOF7PmbJwQ4qDtwpjH3yOVzUL9FC7V2VGEki0xgITOwrSD_uHfXCjZNJhELrno-TwsBaWh0t5Pf__beoT2-0Cw";
        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));
        var signedJWT = assertDoesNotThrow(() -> SignedJWT.parse(jwt));
        assertDoesNotThrow(() -> verifier.verify(signedJWT, "my_nonce"));
    }

    @Test
    void verify_KeyNotInDidLog() {
        signer = assertDoesNotThrow(() -> new EcP256ProofOfPossessionJWSSigner(Path.of("src/test/data/assert-key-01"), didDoc.getId() + "#my-assert-key-01-not-in-doc"));
        var proof = assertDoesNotThrow(() -> new ProofOfPossessionCreator(signer).create(NONCE, ONE_DAY_LONG));

        // for the purpose, you may also use EXAMPLE_POP_JWS_SIGNER_ANOTHER here, instead
        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog)); // CAUTION: Using a whole other key

        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(proof, NONCE));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.KEY_MISMATCH, exc.getErrorCause());
    }

    @Test
    void verify_expired_thenFailure() {
        var jwt = "eyJraWQiOiJkaWQ6d2Vidmg6UW1jS1Z3ak43eTVIOHlaUVlEYWNZeWp1MjluaFZhZXl4VDVROEJWdDNXZmRzbzppZGVudGlmaWVyLXJlZy50cnVzdC1pbmZyYS5zd2l5dS1pbnQuYWRtaW4uY2g6YXBpOnYxOmRpZDoxOGZhN2M3Ny05ZGQxLTRlMjAtYTE0Ny1mYjFiZWMxNDYwODUjbXktYXNzZXJ0LWtleS0wMSIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJkaWQ6d2Vidmg6UW1jS1Z3ak43eTVIOHlaUVlEYWNZeWp1MjluaFZhZXl4VDVROEJWdDNXZmRzbzppZGVudGlmaWVyLXJlZy50cnVzdC1pbmZyYS5zd2l5dS1pbnQuYWRtaW4uY2g6YXBpOnYxOmRpZDoxOGZhN2M3Ny05ZGQxLTRlMjAtYTE0Ny1mYjFiZWMxNDYwODUiLCJleHAiOjE3OTE3MTc5OTQsIm5vbmNlIjoiZXhhbXBsZV9ub25jZSIsImlhdCI6MTc5MTgwNDM5NH0.FJk-jE3gSjOoqRFfm8l7a3wFIvzNb6cRTua6vOk3pkggjST1NvQsniTE8SVV347vke9IlbGyHmu9fw5EfXDPsg";
        var expiredJWT = assertDoesNotThrow(() -> SignedJWT.parse(jwt));
        var e = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(expiredJWT, NONCE));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.EXPIRED, e.getErrorCause());
    }

    @Test
    void verify_nonceMismatch_thenFailure() {
        var nonce = "bar";

        // create proof
        var proof = assertDoesNotThrow(() -> new ProofOfPossessionCreator(signer).create(nonce, ONE_DAY_LONG));

        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(proof, NONCE));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.INVALID_NONCE, exc.getErrorCause());
    }

    @Test
    void verify_issMismatch_thenFailure() { // TODO
        var expiredJWT = assertDoesNotThrow(() -> SignedJWT.parse("eyJraWQiOiJkaWQ6d2Vidmg6UW1jS1Z3ak43eTVIOHlaUVlEYWNZeWp1MjluaFZhZXl4VDVROEJWdDNXZmRzbzppZGVudGlmaWVyLXJlZy50cnVzdC1pbmZyYS5zd2l5dS1pbnQuYWRtaW4uY2g6YXBpOnYxOmRpZDoxOGZhN2M3Ny05ZGQxLTRlMjAtYTE0Ny1mYjFiZWMxNDYwODUjbXktYXNzZXJ0LWtleS0wMSIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJpbnZhbGlkIGlzc3VlciIsImV4cCI6MTc5MTg5MTg2OSwibm9uY2UiOiJleGFtcGxlX25vbmNlIiwiaWF0IjoxNzkxODA1NDY5fQ.v8tM2aO0zR6cQnkUgGvQTguf5j8ot_R-L2CS4AonNcurQiGwH003nMHf66m6RkBDWGvO3BYNBipCqo09l_xz2Q"));
        var e = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(expiredJWT, NONCE));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.FAILED_TO_VERIFY, e.getErrorCause());
    }

    @Test
    void verify_unsupportedAlgorithm_thenFailure() {
        // JWT placeholder from https://www.jwt.io/ using HS256
        var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
        var signedJWT = assertDoesNotThrow(() -> SignedJWT.parse(jwt));
        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));

        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(signedJWT, NONCE));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.UNSUPPORTED_ALGORITHM, exc.getErrorCause());
    }

    @Test
    void verify_unparsableJWT_throwsProofOfPossessionVerifierException() throws ParseException {
        var jwt = mock(SignedJWT.class);
        var header = mock(JWSHeader.class);

        when(jwt.getHeader()).thenReturn(header);
        when(header.getAlgorithm()).thenReturn(JWSAlgorithm.EdDSA);
        when(jwt.getJWTClaimsSet()).thenThrow(new ParseException("mock exception", 1));

        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));
        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(jwt, NONCE));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.KEY_MISMATCH, exc.getErrorCause());
    }

    @Test
    void verify_getNonceThrowsException_throwsProofOfPossessionVerifierException() throws ParseException, JOSEException {
        var jwt = mock(SignedJWT.class);
        var header = mock(JWSHeader.class);
        var claims = mock(JWTClaimsSet.class);

        when(jwt.getHeader()).thenReturn(header);
        when(header.getAlgorithm()).thenReturn(JWSAlgorithm.ES256);
        when(header.getKeyID()).thenReturn(didDoc.getId() + "#my-assert-key-01");
        when(jwt.getJWTClaimsSet()).thenReturn(claims);
        when(jwt.verify(any())).thenReturn(true);
        when(claims.getStringClaim("nonce")).thenThrow(new ParseException("mock exception", 1));

        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));
        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(jwt, NONCE));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.UNPARSABLE, exc.getErrorCause());
    }

    @Test
    void verify_noClaimset_throwsProofOfPosessionVerifierException() throws ParseException, JOSEException {
        var jwt = mock(SignedJWT.class);
        var header = mock(JWSHeader.class);

        when(jwt.getHeader()).thenReturn(header);
        when(header.getAlgorithm()).thenReturn(JWSAlgorithm.ES256);
        when(header.getKeyID()).thenReturn(didDoc.getId() + "#my-assert-key-01");
        when(jwt.getJWTClaimsSet()).thenThrow(new ParseException("mock exception", 1));
        when(jwt.verify(any())).thenReturn(true);

        var verifier = assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog));
        var exc = assertThrowsExactly(ProofOfPossessionVerifierException.class, () -> verifier.verify(jwt, NONCE));
        assertEquals(ProofOfPossessionVerifierException.ErrorCause.UNPARSABLE, exc.getErrorCause());
    }
}
