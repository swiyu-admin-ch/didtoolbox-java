package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.model.TdwDidLogMetaPeeker;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jwt.SignedJWT;

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

    private final Set<String> updateKeys;

    public ProofOfPossessionVerifier(String didLog) throws ProofOfPossessionVerifierException {
        try {
            this.updateKeys = TdwDidLogMetaPeeker.peek(didLog).getParams().getUpdateKeys();
        } catch (DidLogMetaPeekerException e) {
            throw new ProofOfPossessionVerifierException(e);
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
    public void verify(SignedJWT signedJWT, String nonce) throws ProofOfPossessionVerifierException {
        var algorithm = signedJWT.getHeader().getAlgorithm();
        if (!JWSAlgorithm.Ed25519.equals(algorithm)) {
            throw ProofOfPossessionVerifierException.UnsupportedAlgorithm(JWSAlgorithm.Ed25519.toString(), algorithm.toString());
        }

        // check nonce
        String nonceClaim;
        try {
            nonceClaim = signedJWT.getJWTClaimsSet().getStringClaim("nonce");
        } catch (ParseException e) {
            throw ProofOfPossessionVerifierException.Unparsable(e);
        }
        if (!nonce.equals(nonceClaim)) {
            throw ProofOfPossessionVerifierException.InvalidNonce(nonceClaim, nonce);
        }

        // check timestamp
        // ParseException is thrown here, if something's wrong with the provided JWT
        Date expirationTime;
        try {
            expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
        } catch (ParseException e) {
            throw ProofOfPossessionVerifierException.Unparsable(e);
        }
        if (expirationTime == null) {
            throw ProofOfPossessionVerifierException.Expired();
        }
        var now = Instant.now();
        if (now.isAfter(expirationTime.toInstant())) {
            throw ProofOfPossessionVerifierException.Expired();
        }

        // check if the value of JWT claim 'kid' matches the DataIntegrityProof did:key:* value (in DID log)
        var kid = signedJWT.getHeader().getKeyID();
        var publicKeyMultibase = kid.split("#")[1];
        var publicKey = Ed25519Utils.decodeMultibase(publicKeyMultibase);

        if (!this.updateKeys.contains(publicKeyMultibase)) {
            throw ProofOfPossessionVerifierException.KeyMismatch(publicKeyMultibase);
        }

        var jwk = new com.nimbusds.jose.jwk.OctetKeyPair.Builder(
                com.nimbusds.jose.jwk.Curve.Ed25519,
                com.nimbusds.jose.util.Base64URL.encode(publicKey))
                .build();

        try {
            if (!signedJWT.verify(new Ed25519Verifier(jwk.toPublicJWK()))) {
                throw ProofOfPossessionVerifierException.InvalidSignature();
            }
        } catch (JOSEException e) {
            throw ProofOfPossessionVerifierException.FailedToVerify(e);
        }
    }
}
