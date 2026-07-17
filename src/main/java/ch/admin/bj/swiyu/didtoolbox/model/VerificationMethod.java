package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.eid.did_sidekicks.DidSidekicksException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.io.IOException;
import java.nio.file.Path;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;

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
     * The string representation of the
     * <a href="https://www.w3.org/TR/did-1.0/#dfn-verification-method">verification method</a> type behind
     * <a href="https://w3c-ccg.github.io/lds-jws2020/#json-web-key-2020">JsonWebKey2020</a>, which is
     * the type of the verification method for the signature suite {@code JsonWebSignature2020}.
     */
    @Deprecated(since = "2.3.0")
    String VM_TYPE_JSON_WEB_KEY_2020 = "JsonWebKey2020";

    /**
     * Yet another static factory method of the interface.
     * <p>
     * Assuming the supplied {@code publicKeyJwk} represents a proper <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Key (JWK)</a>
     * featuring <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.1">"kty" (Key Type)</a>, {@code crv}, {@code x} and {@code y} parameters,
     * a valid {@link VerificationMethod} implementation object is returned featuring
     * {@link VerificationMethod#getVerificationMaterial()} method that always returns a valid
     * {@link VerificationMaterial} implementation object of type {@code type}
     * (e.g. {@link #VM_TYPE_JSON_WEB_KEY_2020}).
     *
     * @param kid          non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param type         string representation of a <a href="https://www.w3.org/TR/did-1.0/#dfn-verification-method">verification method</a> type
     *                     (e.g. {@link #VM_TYPE_JSON_WEB_KEY_2020})
     * @param publicKeyJwk string representation of a <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Key (JWK)</a>
     * @return a valid {@link VerificationMethod} implementation object, never {@code null}
     * @throws VerificationMethodException if the supplied {@code publicKeyJwk} does not represent a proper
     *                                     <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Key (JWK)</a> as described above
     */
    // Upon removal, move logic to constructor without type parameter
    @Deprecated(since = "2.3.0")
    static VerificationMethod of(String kid, String type, String publicKeyJwk) throws VerificationMethodException {

        JsonObject jsonObj;
        try {
            jsonObj = JsonParser.parseString(publicKeyJwk).getAsJsonObject();
        } catch (JsonSyntaxException exc) {
            throw new VerificationMethodException("The supplied string does not represent a public key JWK", exc);
        }

        var crv = jsonObj.get("crv");
        var x = jsonObj.get("x");
        var y = jsonObj.get("y");

        var kty = jsonObj.get("kty");
        if (kty == null || !kty.isJsonPrimitive()) {
            throw new VerificationMethodException("Expected property 'kty' to be a string.");
        }
        switch (kty.getAsString()) {
            case "OKP" -> {
                if (crv == null || !crv.isJsonPrimitive() || !"Ed25519".equals(crv.getAsString())) {
                    throw new VerificationMethodException("Only curve 'Ed25519' is supported for key type OKP.");
                }
                if (x == null || !x.isJsonPrimitive() || x.getAsString().isEmpty()) {
                    throw new VerificationMethodException("Property 'x' must be set to a string.");
                }
            }
            case "EC" -> {
                if (crv == null || !crv.isJsonPrimitive() || !"P-256".equals(crv.getAsString())) {
                    throw new VerificationMethodException("Only curve 'P-256' is supported for key type EC.");
                }
                if (x == null || !x.isJsonPrimitive() || x.getAsString().isEmpty()) {
                    throw new VerificationMethodException("Property 'x' must be set to a string.");
                }
                if (y == null || !y.isJsonPrimitive() || y.getAsString().isEmpty()) {
                    throw new VerificationMethodException("Property 'y' must be set to a string.");
                }
            }
            default -> {
                throw new VerificationMethodException("Key type %s not supported.".formatted(kty.getAsString()));
            }
        }

        return new VerificationMethod() {

            @Override
            public String getIdFragment() {
                return kid;
            }

            @Override
            public String getType() {
                return type;
            }

            @Override
            public VerificationMaterial getVerificationMaterial() {
                return () -> {
                    jsonObj.addProperty("kid", kid);
                    return jsonObj.toString();
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
     * It is nothing but a variant of the {@link #of(String, String, String)}
     * static factory method having {@link #VM_TYPE_JSON_WEB_KEY_2020} as {@code type}.
     *
     * @see #of(String, String, String)
     * @see #VM_TYPE_JSON_WEB_KEY_2020
     */
    static VerificationMethod of(String kid, String publicKeyJwk) throws VerificationMethodException {
        return VerificationMethod.of(kid, VM_TYPE_JSON_WEB_KEY_2020, publicKeyJwk);
    }

    /**
     * Yet another static factory method of the interface.
     * <p>
     * Assuming the supplied {@code ecPublicKeyPemPath} denotes a file featuring a proper (PEM-encoded) public EC key,
     * a valid {@link VerificationMethod} implementation object is returned featuring
     * {@link VerificationMethod#getVerificationMaterial()} method that always returns a valid
     * {@link VerificationMaterial} implementation object of type {@code type}
     * (e.g. {@link #VM_TYPE_JSON_WEB_KEY_2020}).
     *
     * @param kid              non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param type             string representation of a <a href="https://www.w3.org/TR/did-1.0/#dfn-verification-method">verification method</a> type
     *                         (e.g. {@link #VM_TYPE_JSON_WEB_KEY_2020})
     * @param publicKeyPemPath file featuring a proper P-256 or Ed25519 public key in PEM format
     * @return a valid {@link VerificationMethod} implementation object, never {@code null}
     * @throws VerificationMethodException if the supplied {@code ecPublicKeyPemPath} does not feature a proper public EC key in PEM format
     * @see #of(String, String, String)
     */
    // Upon removal, move logic to constructor without type parameter
    @Deprecated(since = "2.3.0")
    static VerificationMethod of(String kid, String type, Path publicKeyPemPath) throws VerificationMethodException {

        VerificationMaterial vm;
        try {
            vm = VerificationMaterial.of(kid, publicKeyPemPath);
        } catch (IOException | DidSidekicksException exc) {
            throw new VerificationMethodException(exc);
        }

        // Assigning vm to new variable, as the vm cannot be final, as it has "2" assignments
        // even though only 1 of them can work.
        return of(vm);
    }

    /**
     * Yet another static factory method of the interface.
     * <p>
     * It is nothing but a variant of the {@link #of(String, String, Path)}
     * static factory method having {@link #VM_TYPE_JSON_WEB_KEY_2020} as {@code type}.
     *
     * @see #of(String, String, Path)
     * @see #VM_TYPE_JSON_WEB_KEY_2020
     */
    static VerificationMethod of(String kid, Path pemPath) throws VerificationMethodException {
        return VerificationMethod.of(kid, VM_TYPE_JSON_WEB_KEY_2020, pemPath);
    }

    /**
     * Yet another static factory method of the interface.
     * <p>
     * For the supplied public EC key {@code ecPublicKey},
     * a valid {@link VerificationMethod} implementation object is returned featuring
     * {@link VerificationMethod#getVerificationMaterial()} method that always returns a valid
     * {@link VerificationMaterial} implementation object of type {@code type}
     * (e.g. {@link #VM_TYPE_JSON_WEB_KEY_2020}).
     *
     * @param kid         non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param type        string representation of a <a href="https://www.w3.org/TR/did-1.0/#dfn-verification-method">verification method</a> type
     *                    (e.g. {@link #VM_TYPE_JSON_WEB_KEY_2020})
     * @param ecPublicKey valid public EC public key
     * @return a valid {@link VerificationMethod} implementation object, never {@code null}
     * @see VerificationMaterial#of(String, ECPublicKey)
     */
    // Upon removal, move logic to constructor without type parameter
    @Deprecated(since = "2.3.0")
    static VerificationMethod of(String kid, String type, ECPublicKey ecPublicKey) {
        return new VerificationMethod() {
            @Override
            public String getIdFragment() {
                return kid;
            }

            @Override
            public String getType() {
                return type;
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
     * Yet another static factory method of the interface.
     * <p>
     * It is nothing but a variant of the {@link #of(String, String, ECPublicKey)}
     * static factory method having {@link #VM_TYPE_JSON_WEB_KEY_2020} as {@code type}.
     *
     * @see #of(String, String, ECPublicKey)
     * @see #VM_TYPE_JSON_WEB_KEY_2020
     */
    static VerificationMethod of(String kid, ECPublicKey ecPublicKey) {
        return VerificationMethod.of(kid, VM_TYPE_JSON_WEB_KEY_2020, ecPublicKey);
    }

    /**
     * Returns a verification method of the provided material. The fragment is the kid extracted from the material as JWK.
     *
     * @param verificationMaterial to be wrapped
     * @return
     * @throws VerificationMethodException if the provided verificationMaterial returns an invalid JWK or is missing the property 'kid'
     */
    static VerificationMethod of(VerificationMaterial verificationMaterial) throws VerificationMethodException {
        JsonObject jsonObj;
        try {
            jsonObj = JsonParser.parseString(verificationMaterial.getPublicKeyJwk()).getAsJsonObject();
        } catch (JsonSyntaxException exc) {
            throw new VerificationMethodException("The supplied string does not represent a public key JWK", exc);
        }
        var rawKid = jsonObj.get("kid");
        if (rawKid == null || !rawKid.isJsonPrimitive()) {
            throw new VerificationMethodException("Expected JWK to bo present in the JWK as string");
        }
        var kid = rawKid.getAsString();

        return new VerificationMethod() {
            @Override
            public String getIdFragment() {
                return kid;
            }

            @Override
            public String getType() {
                return VM_TYPE_JSON_WEB_KEY_2020;
            }

            @Override
            public VerificationMaterial getVerificationMaterial() {
                return verificationMaterial;
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
    @Deprecated(since = "2.3.0")
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
