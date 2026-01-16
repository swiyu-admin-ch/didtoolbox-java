package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.model.TdwDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.model.WebVerifiableHistoryDidLogMetaPeeker;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.Ed25519VerifyingKey;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import io.ipfs.multibase.Base58;

import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
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
 *
 *         boolean isValid;
 *
 *         try {
 *             var didLog = String.join("\n", Files.readAllLines(Path.of("did.jsonl")));
 *             // may throw ProofOfPossessionVerifierException
 *             var verifier = new ProofOfPossessionVerifier(didLog);
 *             var jwt = SignedJWT.parse(args[0]);
 *             isValid = verifier.isValid(jwt, "Foo");
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

    private Set<String> updateKeys;

    public ProofOfPossessionVerifier(String didLog) throws ProofOfPossessionVerifierException {
        try {
            this.updateKeys = TdwDidLogMetaPeeker.peek(didLog).getParams().getUpdateKeys(); // assume a did:tdw log
        } catch (DidLogMetaPeekerException exc) { // not a did:tdw log
            try {
                this.updateKeys = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getParams().getUpdateKeys(); // assume a did:webvh log
            } catch (DidLogMetaPeekerException exc1) { // not a did:webvh log
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
        if (!JWSAlgorithm.Ed25519.equals(algorithm)) {
            throw ProofOfPossessionVerifierException.unsupportedAlgorithm(JWSAlgorithm.Ed25519.toString(), algorithm.toString());
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

        // check if the value of JWT claim 'kid' matches the DataIntegrityProof did:key:* value (in DID log)
        var kid = signedJWT.getHeader().getKeyID();
        var publicKeyMultibase = kid.split("#")[1];
        byte[] publicKeyBytes;
        // The fromMultibase constructor may denote (via MultibaseConversionFailed error code)
        // that a supplied string value is not multibase-encoded as specified by
        // The Multibase Data Format (https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html)
        try (var ignored = Ed25519VerifyingKey.Companion.fromMultibase(publicKeyMultibase)) {
            var buf = Base58.decode(publicKeyMultibase.substring(1));
            publicKeyBytes = Arrays.copyOfRange(buf, 2, buf.length);
        } catch (DidSidekicksException e) {
            throw ProofOfPossessionVerifierException.malformedClaimKid(e);
        }

        if (!this.updateKeys.contains(publicKeyMultibase)) {
            throw ProofOfPossessionVerifierException.keyMismatch(publicKeyMultibase);
        }

        var jwk = new OctetKeyPair.Builder(
                Curve.Ed25519,
                Base64URL.encode(publicKeyBytes))
                .build();

        Ed25519Verifier verifier;
        try {
            verifier = new Ed25519Verifier(jwk.toPublicJWK());
        } catch (JOSEException ex) { // If the key subtype is not supported
            throw ProofOfPossessionVerifierException.unsupportedKeySubtype();
        }

        boolean verified;
        try {
            verified = signedJWT.verify(verifier);
        } catch (JOSEException e) {
            throw ProofOfPossessionVerifierException.failedToVerify(e);
        }

        if (!verified) {
            throw ProofOfPossessionVerifierException.invalidSignature();
        }
    }
}
