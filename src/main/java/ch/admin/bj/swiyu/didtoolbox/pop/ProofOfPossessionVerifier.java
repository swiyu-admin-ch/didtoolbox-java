package ch.admin.bj.swiyu.didtoolbox.pop;

import ch.admin.bj.swiyu.didtoolbox.did.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.did.tdw.TdwDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryDidLogMetaPeeker;
import ch.admin.eid.did_sidekicks.DidDoc;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.time.Instant;
import java.util.Set;

/**
 * {@link ProofOfPossessionVerifier} is the class in charge of verifying JSON Web Tokens (JWT).
 * <p>
 * It can be used to verify any number of PoP JWTs signed by the owner of the supplied DID log.
 * <p>
 * Example usage:
 * <pre>
 * {@code
 *     package mypackage;
 *
 *     import ch.admin.bj.swiyu.didtoolbox.*;
 *     import com.nimbusds.jwt.SignedJWT;
 *     import java.nio.file.*;
 *
 *     public static void main(String... args) {
 *         boolean isValid;
 *
 *         try {
 *             var didLog = String.join("\n", Files.readAllLines(Path.of("did.jsonl")));
 *             // may throw ProofOfPossessionVerifierException
 *             var verifier = new ProofOfPossessionVerifier(didLog);
 *             var jwt = SignedJWT.parse(args[0]);
 *             isValid = verifier.isValid(jwt, "my nonce");
 *         } catch (Exception e) {
 *             // some exc. handling goes here
 *             System.exit(1);
 *         }
 *
 *         // do something with isValid here
 *     }
 * }
 * </pre>
 */
public class ProofOfPossessionVerifier {

    private DidDoc didDoc;

    public ProofOfPossessionVerifier(DidDoc didDoc) {
        this.didDoc = didDoc;
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    public ProofOfPossessionVerifier(String didLog) throws ProofOfPossessionVerifierException {
        try {
            this.didDoc = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc(); // assume a did:webvh log
        } catch (DidLogMetaPeekerException exc1) { // not a did:webvh log
            try {
                this.didDoc = TdwDidLogMetaPeeker.peek(didLog).getDidDoc(); // assume a did:tdw log
            } catch (DidLogMetaPeekerException exc) { // not a did:tdw log
                throw new ProofOfPossessionVerifierException(exc1);
            }
        }
    }

    /**
     * Verifies if the {@code signedJWT} is valid against the possession {@code nonce}, returning a boolean indicator.
     *
     * @param signedJWT proof of possession to be verified
     * @param nonce     possession
     * @return true if and only if the signedJWT is valid. Otherwise, false.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7800">Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)</a>
     */
    public boolean isValid(SignedJWT signedJWT, String nonce) {
        try {
            verify(signedJWT, nonce);
            return true;
        } catch (ProofOfPossessionVerifierException e) {
            return false;
        }
    }

    /**
     * Verifies if the {@code signedJWT} is valid against the possession {@code nonce}, throwing an exception in case it is
     * invalid. Such exception features some further detailed information.
     *
     * @param signedJWT PoP JWT to be verified
     * @param nonce     possession
     * @throws ProofOfPossessionVerifierException is thrown in case the JWT is invalid, containing more details as to why
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7800">Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)</a>
     */
    @SuppressWarnings("PMD.CyclomaticComplexity") // function doesn't contain complicated logic
    public void verify(SignedJWT signedJWT, String nonce) throws ProofOfPossessionVerifierException {
        // Verify alg
        var algorithm = signedJWT.getHeader().getAlgorithm();
        if (!Set.of(JWSAlgorithm.ES256, JWSAlgorithm.EdDSA).contains(algorithm)) {
            throw ProofOfPossessionVerifierException.unsupportedAlgorithm(algorithm.toString());
        }

        // Retrieve key from DID log for signature verification
        var kid = signedJWT.getHeader().getKeyID();
        if (kid == null) {
            throw ProofOfPossessionVerifierException.keyMismatch("");
        }
        JWK jwk;
        try {
            var key = this.didDoc.getKeyByMethodId(kid);
            if (key == null) {
                throw ProofOfPossessionVerifierException.keyMismatch(kid);
            }
            var objectMapper = new ObjectMapper();
            var jwkString = objectMapper.writeValueAsString(key);
            jwk = JWK.parse(jwkString);
        } catch (DidSidekicksException ignore) {
            throw ProofOfPossessionVerifierException.keyMismatch(kid);
        } catch (ParseException | JsonProcessingException e) {
            throw ProofOfPossessionVerifierException.unparsable(e);
        }

        // Verify signature
        try {
            JWSVerifier jwsVerifier;
            // if else pattern because final class instances cannot be used as cases for a switch statement
            if (JWSAlgorithm.EdDSA.equals(algorithm)) {
                jwsVerifier = new Ed25519Verifier(jwk.toOctetKeyPair());
            } else if (JWSAlgorithm.ES256.equals(algorithm)) {
                jwsVerifier = new ECDSAVerifier(jwk.toECKey());
            } else {
                throw new RuntimeException("Tried to construct a JWS verifier of an algorithm that's not supported and should have been caught earlier."); // NOPMD: code is unreachable
            };

            if (!signedJWT.verify(jwsVerifier)) {
                throw ProofOfPossessionVerifierException.invalidSignature();
            }
        } catch (JOSEException e) { //NOPMD ExceptionAsFlowControl: false positive
            throw ProofOfPossessionVerifierException.failedToVerify(e);
        }

        // ParseException is thrown here, if something's wrong with the provided JWT
        JWTClaimsSet claimSet;
        try {
            claimSet = signedJWT.getJWTClaimsSet();
            // check nonce
            String nonceClaim = claimSet.getStringClaim("nonce");
            if (!MessageDigest.isEqual(nonceClaim.getBytes(StandardCharsets.UTF_8), nonce.getBytes(StandardCharsets.UTF_8))) {
                throw ProofOfPossessionVerifierException.invalidNonce(nonce);
            }
        } catch (ParseException e) { // NOPMD ExceptionAsFlowControl: false positive
            throw ProofOfPossessionVerifierException.unparsable(e);
        }

        var iss = claimSet.getIssuer();
        if (iss != null && !MessageDigest.isEqual(iss.getBytes(StandardCharsets.UTF_8), didDoc.getId().getBytes(StandardCharsets.UTF_8))) {
            throw ProofOfPossessionVerifierException.failedToVerify(new RuntimeException("Iss does not match Id of DID Log"));
        }

        // check timestamp
        var now = Instant.now();
        var expirationTime = claimSet.getExpirationTime();
        if (expirationTime == null || now.isAfter(expirationTime.toInstant())) {
            throw ProofOfPossessionVerifierException.expired();
        }
        var notBeforeTime = claimSet.getNotBeforeTime();
        if (notBeforeTime != null && now.isBefore(notBeforeTime.toInstant())) {
            throw ProofOfPossessionVerifierException.expired();
        }
    }
}
