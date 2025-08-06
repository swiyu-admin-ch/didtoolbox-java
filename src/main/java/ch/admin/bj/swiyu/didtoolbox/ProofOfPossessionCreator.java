package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didtoolbox.TrustDidWeb;
import ch.admin.eid.didtoolbox.TrustDidWebException;
import com.google.gson.JsonParser;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;

import java.io.StringReader;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Objects;

/**
 * {@link ProofOfPossessionCreator} is the class in charge of creating JSON Web Tokens (JWT).
 * <p>
 * Once a {@link ProofOfPossessionCreator} has been instantiated, it can be used to created any number of JWTs belonging to the owner of the DID log.
 * </p>
 *
 * Example usage:
 * <pre>
 * {@code
 *     package mypackage;
 *
 *     import ch.admin.bj.swiyu.didtoolbox.*;
 *     import java.net.*;
 *
 *     public static void main(String... args) {
 *         SignedJWT jwt;
 *
 *         try {
 *             var log = String.join("\n", Files.readAllLines(Path.of("did_log.jsonl")));
 *             var signer = new Ed25519VerificationMethodKeyProviderImpl(new FileReader("src/test/data/private.pem"), new FileReader("src/test/data/public.pem"));
 *             var creator = new ProofOfPossessionCreator(signer, log);
 *             jwt = creator.create("Foo", Duration.ofDays(1));
 *             creator.create("foo", Duration.ofDays(1));
 *         } catch (Exception e) {
 *             // some exc. handling goes here
 *             System.exit(1);
 *         }
 *
 *         // do something with the jwt here
 *     }
 * }
 * </pre>
 */
public class ProofOfPossessionCreator {
    private final VerificationMethodKeyProvider signer;
    private final TrustDidWeb didWeb;

    public ProofOfPossessionCreator(VerificationMethodKeyProvider signer, TrustDidWeb didWeb) {
        this.signer = signer;
        this.didWeb = didWeb;
    }

    public ProofOfPossessionCreator(VerificationMethodKeyProvider signer, String didLog) throws ProofOfPossessionCreatorException {
        this.signer = signer;

        try {
            var didDocId = DidLogMetaPeeker.peek(didLog).didDocId;
            this.didWeb = TrustDidWeb.Companion.read(didDocId, didLog);
        } catch (DidLogMetaPeekerException | TrustDidWebException e) {
            throw new ProofOfPossessionCreatorException(e);
        }

    }

    /**
     * <p>
     * Creates and signs a JWT proof of possession of he nonce.
     * </p>
     *
     * <p>See <a href="https://datatracker.ietf.org/doc/html/rfc7800">Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)</a></p>
     *
     * @param nonce possession
     * @param expiresIn duration from now after which the JWT expires
     * @return proof of possession in form of a JWT
     * @throws IllegalArgumentException when:
     *   it fails to decode the public key from the DID log,
     *   or the keys are not ED25519/EdDSA.
     */
    public SignedJWT create(String nonce, Duration expiresIn) throws ProofOfPossessionCreatorException {
        var str = this.didWeb.getDidLog();
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
                return create(keyID, nonce, expiresIn);
            } catch (JOSEException e) {
                return null;
            }
        }).filter(Objects::nonNull).findFirst();

        if (proof.isEmpty()) {
            throw new ProofOfPossessionCreatorException("TrustDidWeb contained no matching public key to the provided private key");
        }

        return proof.get();
    }

    /**
     * <p>
     * Creates and signs a JWT proof of possession of he nonce.
     * </p>
     *
     * <p>See <a href="https://datatracker.ietf.org/doc/html/rfc7800">Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)</a></p>
     *
     * @param keyID expected value of the verificationMethod of the DID Log
     * @param nonce possession
     * @param expiresIn duration from now after which the JWT expires
     * @return proof of possession in form of a JWT
     * @throws JOSEException when the provided keys are invalid or don't match
     */
    private SignedJWT create(String keyID, String nonce, Duration expiresIn) throws JOSEException {
        var keyParts = keyID.split("#");
        if (keyParts.length != 2) {
            throw new IllegalArgumentException("Expected keyID to contain fragment.");
        }

        var expiration = Date.from(ZonedDateTime.now().plus(expiresIn).toInstant());

        // Prepare header and claims set of the JWT
        var signedJWT = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.Ed25519)
                        .keyID(keyID)
                        .build(),
                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                        .claim("nonce", nonce)
                        .expirationTime(expiration)
                        .build());

        // JOSEException is throw here, if the keys are invalid or don't match
        signedJWT.sign(this.signer);

        return signedJWT;
    }
}
