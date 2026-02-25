package ch.admin.bj.swiyu.didtoolbox;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Date;

/**
 * {@link ProofOfPossessionCreator} is the class in charge of creating JSON Web Tokens (JWT).
 * <p>
 * It can be used to create any number of PoP JWTs belonging to the owner of Ed25519 signing/verifying key pair,
 * used to create/update a DID log. In other words, a JWT header claim {@code kid} value will match an
 * <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">eddsa-jcs-2022 DataIntegrityProof</a>
 * {@code verificationMethod} attribute's value, as seen in any DID log created using the very same
 * {@link ProofOfPossessionJWSSigner} ({@code signer}) object.
 * <p>
 * Example usage:
 * <pre>
 * {@code
 *     package mypackage;
 *
 *     import ch.admin.bj.swiyu.didtoolbox.*;
 *
 *     import com.nimbusds.jwt.SignedJWT;
 *
 *     import java.io.*;
 *     import java.time.Duration;
 *
 *     public static void main(String... args) {
 *
 *         SignedJWT jwt;
 *
 *         try {
 *             var signer = new EcP256ProofOfPossessionJWSSigner(Path.of("src/test/data/assert-key-01"), "did:webvh:exmalpe.com#my-assert-key-01");
 *             var creator = new ProofOfPossessionCreator(signer);
 *             // may throw ProofOfPossessionCreatorException
 *             jwt = creator.create("Foo", Duration.ofDays(1));
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
    private final ProofOfPossessionJWSSigner signer;

    public ProofOfPossessionCreator(ProofOfPossessionJWSSigner signer) {
        this.signer = signer;
    }

    /**
     * <p>
     * Creates a (signed) proof-of-possession JWT of the possession denoted by {@code nonce}.
     * <p>
     * A JWT header claim {@code kid} value will match an <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">eddsa-jcs-2022 DataIntegrityProof</a>
     * {@code verificationMethod} attribute's value, as seen in any DID log created using the very same {@code signer} object (signing key).
     *
     * @param nonce     possession
     * @param expiresIn duration from now after which the JWT expires
     * @return proof of possession JWT
     * @throws ProofOfPossessionCreatorException if the JWS object couldn't be signed
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7800">Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)</a>
     *
     */
    public SignedJWT create(String nonce, Duration expiresIn) throws ProofOfPossessionCreatorException {
        // Prepare header and claims set of the JWT
        var signedJWT = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(signer.getAlgorithm())
                        .keyID(this.signer.getKid())
                        .build(),
                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                        .claim("nonce", nonce)
                        .issuer(signer.getKid().split("#")[0])
                        .issueTime(new Date())
                        .expirationTime(Date.from(ZonedDateTime.now().plus(expiresIn).toInstant()))
                        .build());

        // JOSEException is throw here, if the keys are invalid or don't match
        try {
            signedJWT.sign(this.signer);
        } catch (JOSEException e) {
            throw new ProofOfPossessionCreatorException(e);
        }

        return signedJWT;
    }
}
