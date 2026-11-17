package ch.admin.bj.swiyu.didtoolbox.did.model;

import ch.admin.bj.swiyu.didtoolbox.cryptography.CryptographicAlgorithm;
import ch.admin.bj.swiyu.didtoolbox.cryptography.PemUtils;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.Ed25519VerifyingKey;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import lombok.NonNull;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;

/**
 * A <a href="https://www.w3.org/TR/did-1.0/#dfn-did-documents">DID Document</a> can express
 * <a href="https://www.w3.org/TR/did-1.0/#dfn-verification-method">verification methods</a>,
 * such as cryptographic public keys, which can be used to <a href="https://www.w3.org/TR/did-1.0/#dfn-authenticated">authenticate</a>
 * or authorize interactions with the <a href="https://www.w3.org/TR/did-1.0/#dfn-did-subjects">DID subject</a> or associated parties.
 * <p>
 * The interface also features a several convenient static factory methods focusing on standard Java types typically used for the purpose
 * of holding public EC public keys e.g. {@link ECPublicKey}, {@link Path} or {@link String}.
 *
 * @since 1.9.0
 */
public interface VerificationMethod {

    /**
     * As <a href="https://www.w3.org/TR/did-1.0/#dfn-verificationmethod">specified</a>
     * and w.r.t. <a href="https://www.rfc-editor.org/rfc/rfc3986#section-3.5">RFC3986</a>
     *
     * @return a string that conforms to the <a href="https://www.w3.org/TR/did-1.0/#did-url-syntax">DID URL Syntax</a>
     */
    String getIdFragment();

    /**
     * As <a href="https://www.w3.org/TR/did-1.0/#dfn-verificationmethod">specified</a>
     * and w.r.t. <a href="https://www.rfc-editor.org/rfc/rfc3986#section-3.5">RFC3986</a>
     * the type of the verification method. Possible values should be one of the
     * <a href="https://www.w3.org/TR/did-extensions-properties/#verification-method-types">
     * registered method types</a>
     *
     * @return a string that references exactly one verification method type
     */
    String getType();


    /**
     * @return the public key of the verification method in the method specific form
     */
    String getPublicKey();

    /**
     * Create a verification method entry with set id, type, controller and publicKeyJwk as JsonObject
     * according to swiss-profile-anchor 1.0
     * @param did the did to be used as part of the id together with the idFragment
     * @return the verification method as JsonObject
     */
    default JsonObject toVerificationMethodEntry(String did) {
        var verificationMethodObj = new JsonObject();
        verificationMethodObj.addProperty("id", did + "#" + getIdFragment());
        // The "controller" may be present, if it is it MUST be the DID
        // - https://swiyu-admin-ch.github.io/specifications/swiss-profile-anchor/#512-did-controller
        verificationMethodObj.addProperty("controller", did);
        verificationMethodObj.addProperty("type", getType());
        // CAUTION The exact claim where the public key is depends on the verification method type

        return verificationMethodObj;
    }

    /**
     * Effectively, this is the default {@link Object#equals(Object)} implementation introduced for the sake of preventing:
     * <pre>Default method 'equals' overrides a member of 'java.lang.Object'</pre>
     *
     * @param obj the reference object with which to compare.
     * @return {@code true} if this object is the same as the obj
     * argument; {@code false} otherwise.
     */
    default boolean defaultEquals(Object obj) {
        return (obj instanceof VerificationMethod other) &&
                this.getIdFragment().equals(other.getIdFragment());
    }

    /**
     * Yet another static factory method of the interface.
     * <p>
     * For the supplied public Elliptic Curve key {@code ecPublicKey},
     * a valid {@link VerificationMethod} implementation object is returned featuring {@link #getPublicKey()} method
     * that always returns JSON representation of the Elliptic Curve JWK with any private values removed.
     * The cryptographic curve is always P-256 (secp256r1, also called prime256v1, OID = 1.2.840.10045.3.1.7).
     *
     * @param kid         non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param ecPublicKey The public EC key to represent. Must not be {@code null}
     * @return a valid {@link VerificationMethod} implementation object representing Elliptic Curve JWK with any
     * private values removed, never {@code null}
     */
    static VerificationMethod ofEcPublicKey(String kid, @NonNull ECPublicKey ecPublicKey) throws VerificationMethodException {
        return buildJWKVerificationMethod(kid, parseEcJWK(kid, ecPublicKey));
    }

    /**
     * Yet another static factory method of the interface.
     * <p>
     * For the supplied pem file {@code publicKeyPemFile},
     * a valid {@link VerificationMethod} implementation object is returned featuring {@link #getPublicKey()} method
     * that always returns JSON representation of the JWK with any private values removed.
     * The cryptographic curve is either P-256 (secp256r1, also called prime256v1, OID = 1.2.840.10045.3.1.7) or Ed25519.
     *
     * @param kid              non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param publicKeyPemPath file featuring a proper public P-256 or Ed25519 key in PEM format
     * @return a valid {@link VerificationMethod} implementation object representing Elliptic Curve JWK with any
     * @throws IOException if the supplied {@code ecPublicKeyPemPath} does not feature a proper public EC key in PEM format
     *                     private values removed, never {@code null}
     */
    static VerificationMethod ofPEMPath(String kid, @NonNull Path publicKeyPemPath) throws VerificationMethodException, IOException {
            var pem = Files.readString(publicKeyPemPath);
            return ofPEM(kid, pem);
    }

    static VerificationMethod ofJWK(String kid, String publicKeyJwk) throws VerificationMethodException {
        validateJwk(publicKeyJwk);
        return buildJWKVerificationMethod(kid, publicKeyJwk);
    }

    /**
     * Yet another static factory method of the interface.
     * <p>
     * For the supplied pem file as string {@code pem},
     * a valid {@link VerificationMethod} implementation object is returned featuring {@link #getPublicKey()} method
     * that always returns JSON representation of the JWK with any private values removed.
     * The cryptographic curve is either P-256 (secp256r1, also called prime256v1, OID = 1.2.840.10045.3.1.7) or Ed25519.
     *
     * @param kid non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param pem a proper public ES256 or Ed25519 key in PEM format
     * @return a valid {@link VerificationMethod} implementation object representing Elliptic Curve JWK with any
     *                     private values removed, never {@code null}
     * @throws VerificationMethodException if the supplied key cannot be parsed as a supported public key format
     */
    static VerificationMethod ofPEM(String kid, @NonNull String pem) throws VerificationMethodException {
        try {
            var publicKey = PemUtils.parsePemPublicKey(new StringReader(pem));
            String jwkString = switch (publicKey) {
                case ECPublicKey k -> parseEcJWK(kid, k);
                case EdECPublicKey k -> parseEdJWK(kid, pem);
                default -> throw new VerificationMethodException("provided pem is not supported.");
            };
            return buildJWKVerificationMethod(kid, jwkString);
        } catch (IOException e) {
            throw new VerificationMethodException(e);
        }
    }

    private static String parseEcJWK(String kid, ECPublicKey ecPublicKey) {
        return new ECKey.Builder(Curve.P_256, ecPublicKey).keyID(kid).build().toPublicJWK().toJSONString();
    }

    private static String parseEdJWK(String kid, String pem) throws VerificationMethodException {
        try (var dsaPublicKey = Ed25519VerifyingKey.Companion.fromPublicKeyPem(pem)) {
            var jwk = JsonParser.parseString(dsaPublicKey.toJwk());
            jwk.getAsJsonObject().addProperty("kid", kid);
            return jwk.toString();
        } catch (DidSidekicksException e) {
            throw new VerificationMethodException(e);
        }
    }


    /**
     * Returns a verification method of the provided material. The fragment is the kid extracted from the material as JWK.
     *
     * @param kid non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param jwkString the json web key as stringified json
     * @return A JsonWebKeyVerificationMethod
     * @throws VerificationMethodException if the provided JWK or kid is missing or invalid
     */
    private static VerificationMethod buildJWKVerificationMethod(String kid, String jwkString) throws VerificationMethodException {
        JsonObject jsonObj;
        try {
            jsonObj = JsonParser.parseString(jwkString).getAsJsonObject();
        } catch (JsonSyntaxException exc) {
            throw new VerificationMethodException("The supplied string does not represent a public key JWK", exc);
        }
        if (kid == null || kid.isBlank()) {
            throw new VerificationMethodException("kid is required");
        }

        return new JsonWebKeyVerificationMethod(kid, jsonObj);
    }

    /**
     * Validates that the JWK has the required fields and that the alg is supported by the ecosystem.
     * @param publicKeyJwk to validate
     * @throws VerificationMethodException if the JWK is invalid or not supported
     */
    private static void validateJwk(String publicKeyJwk) throws VerificationMethodException {
        JsonObject jwk = JsonParser.parseString(publicKeyJwk).getAsJsonObject();
        var crv = jwk.get("crv");
        if (crv == null || !crv.isJsonPrimitive()) {
            throw new VerificationMethodException("Property 'crv' is required");
        }

        var kty = jwk.get("kty");
        if (kty == null) {
            throw new VerificationMethodException("Property 'kty' is required.");
        }
        switch (kty.getAsString()) {
            case "OKP" -> {
                if (!CryptographicAlgorithm.ED25519.toString().equals(crv.getAsString())) {
                    throw new VerificationMethodException("Only curve 'Ed25519' is supported for key type OKP.");
                }
            }
            case "EC" -> {
                if (!CryptographicAlgorithm.P256.toString().equals(crv.getAsString())) {
                    throw new VerificationMethodException("Only curve 'P-256' is supported for key type EC.");
                }
                var y = jwk.get("y");
                if (y == null || y.getAsString().isEmpty()) {
                    throw new VerificationMethodException("Property 'y' must be set to a string.");
                }
            }
            default -> throw new VerificationMethodException("Key type %s not supported.".formatted(kty.getAsString()));
        }
        // Both JWK cases require x
        var x = jwk.get("x");
        if (x == null || x.getAsString().isEmpty()) {
            throw new VerificationMethodException("Property 'x' must be set to a string.");
        }
    }
}
