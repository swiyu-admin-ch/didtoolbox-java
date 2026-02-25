package ch.admin.bj.swiyu.didtoolbox.model;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

import java.security.interfaces.ECPublicKey;

/**
 * <a href="https://www.w3.org/TR/did-1.0/#verification-material">Verification material</a> is any information that is used by a process that applies a
 * <a href="https://www.w3.org/TR/did-1.0/#dfn-verification-method">verification method</a>.
 * <p>
 * The interface also features a several convenient static factory methods focusing on standard Java types typically used for the purpose
 * of holding EC/P-256 public keys e.g. {@link ECPublicKey}.
 */
public interface VerificationMaterial {

    /**
     * Yet another static factory method of the interface.
     * <p>
     * Assuming the supplied {@code ecPublicKey} represents a valid EC/P-256 public key,
     * a valid {@link VerificationMaterial} object is returned of type <a href="https://w3c-ccg.github.io/lds-jws2020/">JsonWebKey2020</a>.
     *
     * @param kid         non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param ecPublicKey valid EC/P-256 public key
     * @return a valid {@link VerificationMaterial} implementation object, never {@code null}
     */
    static VerificationMaterial of(String kid, ECPublicKey ecPublicKey) {

        return new VerificationMaterial() {
            @Override
            public String getPublicKeyJwk() {
                return (new ECKey.Builder(Curve.P_256, ecPublicKey)).keyID(kid).build().toPublicJWK().toJSONString();
            }

            @Override
            public String getPublicKeyMultibase() {
                return null;
            }
        };
    }

    /**
     * As <a href="https://www.w3.org/TR/did-1.0/#dfn-publickeyjwk">specified</a>:
     * <pre>
     * The publicKeyJwk property is OPTIONAL. If present, the value MUST be a map representing a JSON Web Key that conforms to [RFC7517].
     * The map MUST NOT contain "d", or any other members of the private information class as described in Registration Template.
     * It is RECOMMENDED that verification methods that use JWKs [RFC7517] to represent their public keys use the value of kid as their fragment identifier.
     * It is RECOMMENDED that JWK kid values are set to the public key fingerprint [RFC7638].
     * </pre>
     *
     * @return a string representing a JSON Web Key that conforms to <a href="https://www.rfc-editor.org/rfc/rfc7517">RFC7517</a>.
     * Or {@code null} denoting its optional nature.
     */
    String getPublicKeyJwk();

    /**
     * As <a href="https://www.w3.org/TR/did-1.0/#dfn-publickeymultibase">specified</a>:
     * <pre>
     * The publicKeyMultibase property is OPTIONAL. This feature is non-normative.
     * If present, the value MUST be a string representation of a [MULTIBASE] encoded public key.
     * </pre>
     *
     * @return a string representation of a [MULTIBASE] encoded public key.
     * Or {@code null} denoting its optional nature.
     */
    String getPublicKeyMultibase();
}
