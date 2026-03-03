package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.PemUtils;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.ECPublicKey;

/**
 * <a href="https://www.w3.org/TR/did-1.0/#verification-material">Verification material</a> is any information that is used by a process that applies a
 * <a href="https://www.w3.org/TR/did-1.0/#dfn-verification-method">verification method</a>.
 * <p>
 * This interface models <a href="https://www.w3.org/TR/did-1.0/#verification-material">verification material</a> with sole focus on
 * <a href="https://www.w3.org/TR/did-1.0/#dfn-publickeyjwk">publicKeyJwk</a> property. Ergo, beware that also optional
 * <a href="https://www.w3.org/TR/did-1.0/#dfn-publickeymultibase">publicKeyMultibase</a> property is at this point not
 * (yet) relevant for the interface and therefore not (yet) modeled.
 * <p>
 * The interface also features a several convenient static factory methods focusing on standard Java types typically used for the purpose
 * of holding public EC keys, e.g. {@link ECPublicKey} or {@link Path}.
 *
 * @since 1.9.0
 */
public interface VerificationMaterial {

    /**
     * Yet another static factory method of the interface.
     * <p>
     * For the supplied public Elliptic Curve key {@code ecPublicKey},
     * a valid {@link VerificationMaterial} implementation object is returned featuring {@link #getPublicKeyJwk()} method
     * that always returns JSON representation of the Elliptic Curve JWK with any private values removed.
     * The cryptographic curve is always P-256 (secp256r1, also called prime256v1, OID = 1.2.840.10045.3.1.7).
     *
     * @param kid         non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param ecPublicKey The public EC key to represent. Must not be {@code null}
     * @return a valid {@link VerificationMaterial} implementation object representing Elliptic Curve JWK with any
     * private values removed, never {@code null}
     */
    static VerificationMaterial of(String kid, ECPublicKey ecPublicKey) {

        return () -> (new ECKey.Builder(Curve.P_256, ecPublicKey)).keyID(kid).build().toPublicJWK().toJSONString();
    }

    /**
     * Yet another static factory method of the interface.
     * <p>
     * For the supplied public Elliptic Curve key {@code ecPublicKey},
     * a valid {@link VerificationMaterial} implementation object is returned featuring {@link #getPublicKeyJwk()} method
     * that always returns JSON representation of the Elliptic Curve JWK with any private values removed.
     * The cryptographic curve is always P-256 (secp256r1, also called prime256v1, OID = 1.2.840.10045.3.1.7).
     *
     * @param kid                non-empty string representing a <a href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">"kid" (Key ID) Parameter</a>
     * @param ecPublicKeyPemPath file featuring a proper public EC key in PEM format
     * @return a valid {@link VerificationMaterial} implementation object representing Elliptic Curve JWK with any
     * @throws IOException if the supplied {@code ecPublicKeyPemPath} does not feature a proper public EC key in PEM format
     * private values removed, never {@code null}
     */
    static VerificationMaterial of(String kid, Path ecPublicKeyPemPath) throws IOException {
        var ecPublicKey = (ECPublicKey) PemUtils.parsePemPublicKey(Files.newBufferedReader(ecPublicKeyPemPath));
        return () -> (new ECKey.Builder(Curve.P_256, ecPublicKey)).keyID(kid).build().toPublicJWK().toJSONString();
    }

    /**
     * As <a href="https://www.w3.org/TR/did-1.0/#dfn-publickeyjwk">specified</a>:
     * <pre>
     * The {@code publicKeyJwk} property is OPTIONAL. If present, the value MUST be a map representing a JSON Web Key that conforms to [RFC7517].
     * The map MUST NOT contain "d", or any other members of the private information class as described in Registration Template.
     * It is RECOMMENDED that verification methods that use JWKs [RFC7517] to represent their public keys use the value of kid as their fragment identifier.
     * It is RECOMMENDED that JWK kid values are set to the public key fingerprint [RFC7638].
     * </pre>
     *
     * @return a string representing a JSON Web Key that conforms to <a href="https://www.rfc-editor.org/rfc/rfc7517">RFC7517</a>.
     * Or {@code null} denoting its optional nature.
     */
    String getPublicKeyJwk();
}
