package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didtoolbox.TrustDidWeb;
import ch.admin.eid.didtoolbox.TrustDidWebException;
import com.google.gson.JsonParser;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;

import java.io.StringReader;
import java.security.*;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Set;

/**
 * {@link ProofOfPossessionVerifier} is the class in charge of verifying JSON Web Tokens (JWT).
 * <p>
 * Once a {@link ProofOfPossessionVerifier} has been instantiated, it can be used to verify any number of JWTs that were signed by the owner of the provided DID log.
 * </p>
 *
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
 *         try {
 *             var log = String.join("\n", Files.readAllLines(Path.of("did_log.jsonl")));
 *             var verifier = new ProofOfPossessionVerifier(log);
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
    private static final JWSAlgorithm SUPPORTED_JWS_ALGORITHM = JWSAlgorithm.Ed25519;

    private final TrustDidWeb didWeb;

    public ProofOfPossessionVerifier(TrustDidWeb didWeb) {
        this.didWeb = didWeb;
    }

    public ProofOfPossessionVerifier(String didLog) throws ProofOfPossessionVerifierException {
        try {
            var didDocId = DidLogMetaPeeker.peek(didLog).didDocId;
            this.didWeb = TrustDidWeb.Companion.read(didDocId, didLog);
        } catch (DidLogMetaPeekerException | TrustDidWebException e) {
            throw new ProofOfPossessionVerifierException(e);
        }
    }

    /**
     * <p>
     * Verifies the validity of the signedJWT.
     * </p>
     *
     * <p>See <a href="https://datatracker.ietf.org/doc/html/rfc7800>Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)</a></p>
     *
     * @param signedJWT proof of possession to be verified
     * @param nonce possession
     * @return
     * @throws ParseException
     * @throws JOSEException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public boolean isValid(SignedJWT signedJWT, String nonce) throws ParseException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            verify(signedJWT, nonce);
            return true;
        } catch (ProofOfPossessionVerifierException e) {
            return false;
        }
    }

    /**
     * <p>
     * Verifies the validity of the signedJWT, throwing an error in case it is invalid containing further information.
     * </p>
     *
     * <p>See <a href="https://datatracker.ietf.org/doc/html/rfc7800>Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)</a></p>
     *
     * @param signedJWT proof of possession to be verified
     * @param nonce possession
     * @throws ProofOfPossessionVerifierException is thrown in case the JWT is invalid, containing more details as to why
     * @throws ParseException if the JWT is malformed
     * @throws JOSEException when the provided keys are invalid or don't match
     */
    public void verify(SignedJWT signedJWT, String nonce) throws ProofOfPossessionVerifierException, ParseException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException {
        var algorithm = signedJWT.getHeader().getAlgorithm();
        if (!SUPPORTED_JWS_ALGORITHM.equals(algorithm)) {
            throw ProofOfPossessionVerifierException.UnsupportedAlgorithm(SUPPORTED_JWS_ALGORITHM.toString(), algorithm.toString());
        }

        // check nonce
        var claimedNonce =  signedJWT.getJWTClaimsSet().getStringClaim("nonce");
        if (!nonce.equals(claimedNonce)) {
            throw ProofOfPossessionVerifierException.InvalidNonce(claimedNonce, nonce);
        }

        // check timestamp
        // ParseException is thrown here, if something's wrong with the provided JWT
        var expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
        if (expirationTime == null) {
            throw ProofOfPossessionVerifierException.Expired();
        }
        var now = Instant.now();
        if (now.isAfter(expirationTime.toInstant())) {
            throw ProofOfPossessionVerifierException.Expired();
        }

        // check if kid belongs to did
        // ParseException is thrown here, if something's wrong with the provided JWT
        var kid = signedJWT.getHeader().getKeyID();

        var str = didWeb.getDidLog();
        var reader = new JsonReader(new StringReader(str));
        reader.setStrictness(Strictness.LENIENT);
        var did = JsonParser.parseReader(reader).getAsJsonArray();
        if (did.size() != 5) {
            throw new IllegalArgumentException("Malformed DID log");
        }

        var dataIntegrityProofs = did.get(4).getAsJsonArray();
        var containsKey = dataIntegrityProofs.asList().stream().anyMatch(dataIntegrityProof -> {
            var keyID = dataIntegrityProof.getAsJsonObject().get("verificationMethod").getAsString();
            return kid.equals(keyID);
        });
        if (!containsKey) {
            throw ProofOfPossessionVerifierException.KeyNotFound(kid);
        }

        var publicKeyMultibase = kid.split("#")[1];
        var publicKey = Ed25519Utils.decodeMultibase(publicKeyMultibase);

        var jwk = new com.nimbusds.jose.jwk.OctetKeyPair.Builder(
                com.nimbusds.jose.jwk.Curve.Ed25519,
                com.nimbusds.jose.util.Base64URL.encode(publicKey))
                .build();

        // JOSEException is throw here, if the keys are invalid or don't match
        var verifier = new Ed25519Verifier(jwk.toPublicJWK());
        if (!signedJWT.verify(verifier)) {
            throw ProofOfPossessionVerifierException.InvalidSignature();
        }
    }
}
