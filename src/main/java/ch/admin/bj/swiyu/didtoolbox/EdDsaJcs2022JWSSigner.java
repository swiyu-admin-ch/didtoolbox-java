package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.Set;

/**
 * This {@link ProofOfPossessionJWSSigner} implementation builds on top of {@link EdDsaJcs2022VcDataIntegrityCryptographicSuite}
 * aiming at reusing the extensive key loading facilities from the base class.
 * <p>
 * To be used in conjunction with {@link ProofOfPossessionCreator#ProofOfPossessionCreator(ProofOfPossessionJWSSigner)}.
 *
 * @since 1.8.0
 */
public class EdDsaJcs2022JWSSigner extends EdDsaJcs2022VcDataIntegrityCryptographicSuite implements JWSSigner {
    private final String kid;

    /**
     * @see EdDsaJcs2022VcDataIntegrityCryptographicSuite#EdDsaJcs2022VcDataIntegrityCryptographicSuite(Path)
     */
    public EdDsaJcs2022JWSSigner(Path pkcs8PemPath, String kid) throws VcDataIntegrityCryptographicSuiteException {
        super(pkcs8PemPath);
        this.kid = kid;
    }

    /**
     * @see EdDsaJcs2022VcDataIntegrityCryptographicSuite#EdDsaJcs2022VcDataIntegrityCryptographicSuite(InputStream, String, String, String)
     */
    public EdDsaJcs2022JWSSigner(InputStream jksFile, String password, String alias, String keyPassword, String kid)
            throws VcDataIntegrityCryptographicSuiteException {
        super(jksFile, password, alias, keyPassword);
        this.kid = kid;
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.Ed25519);
    }

    @Override
    public Base64URL sign(JWSHeader jwsHeader, byte[] bytes) throws JOSEException {
        return Base64URL.encode(super.generateSignature(bytes));
    }

    @Override
    public JCAContext getJCAContext() {
        return null;
    }
}
