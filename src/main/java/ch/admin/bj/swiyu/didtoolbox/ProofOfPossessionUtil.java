package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didtoolbox.*;
import com.google.gson.JsonParser;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jwt.SignedJWT;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

public class ProofOfPossessionUtil {
    private static final String SUPPORTED_ALGORITHM = "EdDSA";
    private static final JWSAlgorithm SUPPORTED_JWS_ALGORITHM = JWSAlgorithm.Ed25519;
    private static final Duration VALID_DURATION = Duration.ofDays(1);

    /**
     * <p>
     * Verifies the validity of the signedJWT.
     * </p>
     *
     * <p>See <a href="https://datatracker.ietf.org/doc/html/rfc7800>Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)</a></p>
     *
     * @param signedJWT proof of possession to be verified
     * @param nonce possession
     * @param didWeb DID log of the owner
     * @return
     * @throws ParseException
     * @throws JOSEException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static boolean isValid(SignedJWT signedJWT, String nonce, TrustDidWeb didWeb) throws ParseException, JOSEException {
        try {
            verify(signedJWT, nonce, didWeb);
            return true;
        } catch (ProofOfPossessionVerificationException e) {
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
     * @param didWeb DID log of the owner
     * @throws ProofOfPossessionVerificationException is thrown in case the JWT is invalid, containing more details as to why
     * @throws ParseException if the JWT is malformed
     * @throws JOSEException when the provided keys are invalid or don't match
     */
    public static void verify(SignedJWT signedJWT, String nonce, TrustDidWeb didWeb) throws ProofOfPossessionVerificationException, ParseException, JOSEException {
        var algorithm = signedJWT.getHeader().getAlgorithm();
        if (!SUPPORTED_JWS_ALGORITHM.equals(algorithm)) {
            throw ProofOfPossessionVerificationException.UnsupportedAlgorithm(SUPPORTED_JWS_ALGORITHM.toString(), algorithm.toString());
        }

        // check nonce
        var claimedNonce =  signedJWT.getJWTClaimsSet().getStringClaim("nonce");
        if (!nonce.equals(claimedNonce)) {
            throw ProofOfPossessionVerificationException.InvalidNonce(claimedNonce, nonce);
        }

        // check timestamp
        // ParseException is thrown here, if something's wrong with the provided JWT
        var expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
        if (expirationTime == null) {
            throw ProofOfPossessionVerificationException.Expired();
        }
        var now = Instant.now();
        if (now.isAfter(expirationTime.toInstant())) {
            throw ProofOfPossessionVerificationException.Expired();
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
            throw ProofOfPossessionVerificationException.KeyNotFound(kid);
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
            throw ProofOfPossessionVerificationException.InvalidSignature();
        }
    }

    /**
     * <p>
     * Creates and signs a JWT proof of possession of he nonce.
     * The expiration date is now {@link #VALID_DURATION} hours after creation.
     * </p>
     *
     * <p>See <a href="https://datatracker.ietf.org/doc/html/rfc7800">Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)</a></p>
     *
     * @param privateKey to sign JWT
     * @param didWeb DID log of the owner
     * @param nonce possession
     * @return proof of possession in form of a JWT
     * @throws IllegalArgumentException when:
     *   it fails to decode the public key from the DID log,
     *   or the keys are not ED25519/EdDSA.
     */
    public static SignedJWT createProofOfPossession(PrivateKey privateKey, TrustDidWeb didWeb, String nonce) {
        if (!SUPPORTED_ALGORITHM.equals(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("Expected private key to be of algorithm EdDSA");
        }

        var str = didWeb.getDidLog();
        var reader = new JsonReader(new StringReader(str));
        reader.setStrictness(Strictness.LENIENT);
        var did = JsonParser.parseReader(reader).getAsJsonArray();
        if (did.size() != 5) {
            throw new IllegalArgumentException();
        }

        var dataIntegrityProofs = did.get(4).getAsJsonArray();
        // try public key of every dataIntegrityProof
        var proof = dataIntegrityProofs.asList().stream().map(dataIntegrityProof -> {
            var keyID = dataIntegrityProof.getAsJsonObject().get("verificationMethod").getAsString();
            try {
                return ProofOfPossessionUtil.createProofOfPossession(privateKey, keyID, nonce);
            } catch (JOSEException e) {
                return null;
            }
        }).filter(Objects::nonNull).findFirst();

        if (proof.isEmpty()) {
            throw new IllegalArgumentException("TrustDidWeb contained no matching public key to the provided private key");
        }

        return proof.get();
    }

    /**
     * <p>
     * Creates and signs a JWT proof of possession of he nonce.
     * The expiration date is now {@link #VALID_DURATION} hours after creation.
     * </p>
     *
     * <p>See <a href="https://datatracker.ietf.org/doc/html/rfc7800">Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)</a></p>
     *
     * @param privateKey to sign JWT
     * @param keyID expected value of the verificationMethod of the DID Log
     * @param nonce possession
     * @return proof of possession in form of a JWT
     * @throws JOSEException when the provided keys are invalid or don't match
     */
    private static SignedJWT createProofOfPossession(PrivateKey privateKey, String keyID, String nonce) throws JOSEException {
        var keyParts = keyID.split("#");
        if (keyParts.length != 2) {
            throw new IllegalArgumentException("Expected keyID to contain fragment.");
        }
        byte[] publicKey;
        try {
            publicKey = Ed25519Utils.decodeMultibase(keyParts[1]);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Failed to decode public key from fragment.", e);
        }

        // Prepare header and claims set of the JWT
        var signedJWT = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.Ed25519)
                        .keyID(keyID)
                        .build(),
                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                        .claim("nonce", nonce)
                        .expirationTime(java.util.Date.from(java.time.ZonedDateTime.now().plus(VALID_DURATION).toInstant()))
                        .build());

        var fullPrivateKeyBytes = privateKey.getEncoded();
        var privateKeyBytes = Arrays.copyOfRange(fullPrivateKeyBytes, fullPrivateKeyBytes.length-32, fullPrivateKeyBytes.length);

        // Generate a key pair with Ed25519 curve
        var jwk = new com.nimbusds.jose.jwk.OctetKeyPair.Builder(
                com.nimbusds.jose.jwk.Curve.Ed25519,
                com.nimbusds.jose.util.Base64URL.encode(publicKey))
                .d(com.nimbusds.jose.util.Base64URL.encode(privateKeyBytes))
                .build();

        // JOSEException is throw here, if the keys are invalid or don't match
        var signer = new Ed25519Signer(jwk);
        signedJWT.sign(signer);

        return signedJWT;
    }
}
