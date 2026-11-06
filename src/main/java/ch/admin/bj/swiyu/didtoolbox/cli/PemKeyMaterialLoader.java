package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cryptography.ProofOfPossessionJWSSigner;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.JOSEException;

import java.io.IOException;
import java.nio.file.Path;

/**
 * {@link KeyMaterialLoader} reading the private key from a PEM file.
 */
final class PemKeyMaterialLoader implements KeyMaterialLoader {

    private final Path signingKeyPemFile;

    PemKeyMaterialLoader(Path signingKeyPemFile) {
        this.signingKeyPemFile = signingKeyPemFile;
    }

    @Override
    public VcDataIntegrityCryptographicSuite loadCryptographicSuite() throws VcDataIntegrityCryptographicSuiteException {
        return new EdDsaJcs2022VcDataIntegrityCryptographicSuite(signingKeyPemFile);
    }

    @Override
    public ProofOfPossessionJWSSigner loadProofOfPossessionSigner(String kid)
            throws IOException, JOSEException, VcDataIntegrityCryptographicSuiteException {
        return ProofOfPossessionJWSSigner.of(signingKeyPemFile, kid);
    }
}
