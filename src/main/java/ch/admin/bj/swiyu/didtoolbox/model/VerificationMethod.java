package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.io.IOException;
import java.nio.file.Path;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

/**
 * A <a href="https://www.w3.org/TR/did-1.0/#dfn-did-documents">DID Document</a> can express
 * <a href="https://www.w3.org/TR/did-1.0/#dfn-verification-method">verification methods</a>,
 * such as cryptographic public keys, which can be used to <a href="https://www.w3.org/TR/did-1.0/#dfn-authenticated">authenticate</a>
 * or authorize interactions with the <a href="https://www.w3.org/TR/did-1.0/#dfn-did-subjects">DID subject</a> or associated parties.
 * <p>
 * The interface also features a several convenient static factory methods focusing on standard Java types typically used for the purpose
 * of holding EC/P-256 public keys e.g. {@link ECPublicKey}, {@link Path} or {@link String}.
 */
public interface VerificationMethod {

    /**
     * Yet another static factory method of the interface.
     * <p>
     * Assuming the supplied {@code publicKeyJwk} represents a proper EC/P-256 <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Key (JWK)</a>,
     * a valid {@link VerificationMethod} object is returned of type <a href="https://w3c-ccg.github.io/lds-jws2020/">JsonWebKey2020</a>.
     *
     * @param kid          non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param publicKeyJwk string representation of a <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Key (JWK)</a>
     * @return a valid {@link VerificationMethod} implementation object, never {@code null}
     * @throws VerificationMethodException if the supplied {@code publicKeyJwk} does not represent a proper
     *                                     <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Key (JWK)</a>
     */
    static VerificationMethod of(String kid, String publicKeyJwk) throws VerificationMethodException {

        JsonObject jsonObj;
        try {
            jsonObj = JsonParser.parseString(publicKeyJwk).getAsJsonObject();
        } catch (JsonSyntaxException exc) {
            throw new VerificationMethodException("The supplied string does not represent a public key JWK", exc);
        }

        var kty = jsonObj.get("kty");
        var crv = jsonObj.get("crv");
        var x = jsonObj.get("x");
        var y = jsonObj.get("y");
        if (kty == null || crv == null || x == null || y == null) {
            throw new VerificationMethodException("The supplied string representing a public key JWK does not feature all the required parameters ('kty', 'crv', 'x' or 'y'");
        }

        return new VerificationMethod() {

            @Override
            public String getIdFragment() {
                return kid;
            }

            @Override
            public String getType() {
                return "JsonWebKey2020";
            }

            @Override
            public VerificationMaterial getVerificationMaterial() {
                return new VerificationMaterial() {
                    @Override
                    public String getPublicKeyJwk() {
                        jsonObj.addProperty("kid", kid);
                        return jsonObj.toString();
                    }

                    @Override
                    public String getPublicKeyMultibase() {
                        return null;
                    }
                };
            }

            @Override
            public boolean equals(Object obj) {
                return this.defaultEquals(obj);
            }

            @Override
            public int hashCode() {
                return Objects.hash(this.getIdFragment());
            }
        };
    }

    /**
     * Yet another static factory method of the interface.
     * <p>
     * Assuming the supplied {@code pemPath} denotes a file featuring a proper EC/P-256 public key,
     * a valid {@link VerificationMethod} object is returned of type <a href="https://w3c-ccg.github.io/lds-jws2020/">JsonWebKey2020</a>.
     *
     * @param kid     non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param pemPath file featuring a proper EC/P-256 public key in PEM format
     * @return a valid {@link VerificationMethod} implementation object, never {@code null}
     * @throws VerificationMethodException if the supplied {@code pemPath} does not feature a proper EC/P-256 public key in PEM format
     */
    static VerificationMethod of(String kid, Path pemPath) throws VerificationMethodException {
        try {
            return VerificationMethod.of(kid, JwkUtils.loadECPublicJWKasJSON(pemPath, kid));
        } catch (IOException | InvalidKeySpecException exc) {
            throw new VerificationMethodException(exc);
        }
    }

    /**
     * Yet another static factory method of the interface.
     * <p>
     * Assuming the supplied {@code publicKeyJwk} represents a valid EC/P-256 public key,
     * a valid {@link VerificationMethod} object is returned of type <a href="https://w3c-ccg.github.io/lds-jws2020/">JsonWebKey2020</a>.
     *
     * @param kid         non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param ecPublicKey valid EC/P-256 public key
     * @return a valid {@link VerificationMethod} implementation object, never {@code null}
     */
    static VerificationMethod of(String kid, ECPublicKey ecPublicKey) {
        return new VerificationMethod() {
            @Override
            public String getIdFragment() {
                return kid;
            }

            @Override
            public String getType() {
                return "JsonWebKey2020";
            }

            @Override
            public VerificationMaterial getVerificationMaterial() {
                return VerificationMaterial.of(kid, ecPublicKey);
            }

            @Override
            public boolean equals(Object obj) {
                return this.defaultEquals(obj);
            }

            @Override
            public int hashCode() {
                return Objects.hash(this.getIdFragment());
            }
        };
    }

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
     *
     * @return a string that references exactly one verification method type
     */
    String getType();

    /**
     * As <a href="https://www.w3.org/TR/did-1.0/#verification-material">specified</a>:
     * <p>
     * <a href="https://www.w3.org/TR/did-1.0/#verification-material">Verification material</a> is any information that is used by a process that applies a
     * <a href="https://www.w3.org/TR/did-1.0/#dfn-verification-method">verification method</a>.
     *
     * @return a valid {@link VerificationMaterial} implementation object, never {@code null}
     */
    VerificationMaterial getVerificationMaterial();

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
}
