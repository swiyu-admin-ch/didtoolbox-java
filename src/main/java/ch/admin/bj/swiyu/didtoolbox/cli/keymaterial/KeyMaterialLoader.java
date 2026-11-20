package ch.admin.bj.swiyu.didtoolbox.cli.keymaterial;

import ch.admin.bj.swiyu.didtoolbox.cryptography.ProofOfPossessionJWSSigner;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.JOSEException;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Abstraction of a single source of (signing/verifying) key material supplied via CLI, e.g. PEM files, a Java KeyStore or
 * a Securosys Primus (HSM) connection.
 * <p>
 * The CLI advertises these sources as mutually exclusive, so exactly one implementation is ever picked per command run.
 * Adding a further key source boils down to adding a further implementation, teaching the {@link KeyMaterialLoaderFactory}
 * about it and having the commands supporting that key source call the factory.
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface") // not intended as lambda target, implementations carry key material state
public interface KeyMaterialLoader {

    /**
     * Loads the key material as cryptographic suite, suitable for signing DID log entries.
     *
     * @return the cryptographic suite, never {@code null}
     * @throws VcDataIntegrityCryptographicSuiteException if the key material cannot be loaded
     */
    VcDataIntegrityCryptographicSuite loadCryptographicSuite() throws VcDataIntegrityCryptographicSuiteException;

    /**
     * Loads the key material as JWS signer, suitable for signing proof of possession JWTs.
     *
     * @param kid to be included in the JWT header
     * @return the signer, never {@code null}
     * @throws UnsupportedOperationException if the key source is not supported for signing proof of possession JWTs
     */
    default ProofOfPossessionJWSSigner loadProofOfPossessionSigner(String kid)
            throws IOException, GeneralSecurityException, JOSEException, VcDataIntegrityCryptographicSuiteException {
        throw new UnsupportedOperationException("The supplied source of keys is not supported for signing proof of possession JWTs");
    }
}
