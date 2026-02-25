package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.model.TdwDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.model.WebVerifiableHistoryDidLogMetaPeeker;
import ch.admin.eid.did_sidekicks.DidDoc;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
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
    @SuppressWarnings({"PMD.CyclomaticComplexity"})
    public void verify(SignedJWT signedJWT, String nonce) throws ProofOfPossessionVerifierException {
        var algorithm = signedJWT.getHeader().getAlgorithm();
        if (!Set.of(JWSAlgorithm.Ed25519, JWSAlgorithm.ES256).contains(algorithm)) {
            throw ProofOfPossessionVerifierException.unsupportedAlgorithm(algorithm.toString());
        }

        // check nonce
        String nonceClaim;
        try {
            nonceClaim = signedJWT.getJWTClaimsSet().getStringClaim("nonce");
        } catch (ParseException e) {
            throw ProofOfPossessionVerifierException.unparsable(e);
        }
        if (!nonce.equals(nonceClaim)) {
            throw ProofOfPossessionVerifierException.invalidNonce(nonceClaim, nonce);
        }

        // check timestamp
        // ParseException is thrown here, if something's wrong with the provided JWT
        Date expirationTime;
        try {
            expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
        } catch (ParseException e) {
            throw ProofOfPossessionVerifierException.unparsable(e);
        }
        if (expirationTime == null) {
            throw ProofOfPossessionVerifierException.expired();
        }
        var now = Instant.now();
        if (now.isAfter(expirationTime.toInstant())) {
            throw ProofOfPossessionVerifierException.expired();
        }


        // retrieve key
        var kid = signedJWT.getHeader().getKeyID();
        var keyIdSplit = kid.split("#");
        if (keyIdSplit.length != 2) {
            throw ProofOfPossessionVerifierException.malformedClaimKid("provided kid does not have fragment");
        }

        // retrieve key
        JWK jwk;
        try {
            var objectMapper = new ObjectMapper();
            var jwkString = objectMapper.writeValueAsString(this.didDoc.getKey(keyIdSplit[1]));
            jwk = JWK.parse(jwkString);
        } catch (DidSidekicksException e) {
            throw ProofOfPossessionVerifierException.keyMismatch(kid);
        } catch (ParseException | JsonProcessingException e) {
            throw ProofOfPossessionVerifierException.unparsable(e);
        }

        try {
            JWSVerifier jwsVerifier = new ECDSAVerifier(jwk.toECKey());
            if (!signedJWT.verify(jwsVerifier)) {
                throw ProofOfPossessionVerifierException.invalidSignature();
            }
        } catch (JOSEException e) {
            throw ProofOfPossessionVerifierException.failedToVerify(e);
        }
    }
}
