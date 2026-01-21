package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.JWSAlgorithm;

import java.io.File;
import java.io.InputStream;
import java.util.Set;

/**
 * This {@link ProofOfPossessionJWSSigner} implementation builds on top of {@link EdDsaJcs2022VcDataIntegrityCryptographicSuite}
 * aiming at reusing the extensive key loading facilities from the base class.
 * <p>
 * To be used in conjunction with {@link ProofOfPossessionCreator#ProofOfPossessionCreator(ProofOfPossessionJWSSigner)}.
 *
 * @since 1.8.0
 */
public class EdDsaJcs2022ProofOfPossessionJWSSigner extends EdDsaJcs2022VcDataIntegrityCryptographicSuite implements ProofOfPossessionJWSSigner {

    /**
     * @see EdDsaJcs2022VcDataIntegrityCryptographicSuite#EdDsaJcs2022VcDataIntegrityCryptographicSuite(File)
     */
    public EdDsaJcs2022ProofOfPossessionJWSSigner(File pkcs8PemFile) throws VcDataIntegrityCryptographicSuiteException {
        super(pkcs8PemFile);
    }

    /**
     * @see EdDsaJcs2022VcDataIntegrityCryptographicSuite#EdDsaJcs2022VcDataIntegrityCryptographicSuite(InputStream, String, String, String)
     */
    public EdDsaJcs2022ProofOfPossessionJWSSigner(InputStream jksFile, String password, String alias, String keyPassword)
            throws VcDataIntegrityCryptographicSuiteException {
        super(jksFile, password, alias, keyPassword);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.Ed25519);
    }
}
