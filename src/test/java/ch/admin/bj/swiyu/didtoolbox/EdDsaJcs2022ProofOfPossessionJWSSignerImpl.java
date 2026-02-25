package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import lombok.Getter;

import java.util.Set;

/**
 * Intended for unit testing purposes only.
 */
//@SuppressWarnings("PMD")
class EdDsaJcs2022ProofOfPossessionJWSSignerImpl extends EdDsaJcs2022VcDataIntegrityCryptographicSuite implements ProofOfPossessionJWSSigner {
    private final String kid;

    EdDsaJcs2022ProofOfPossessionJWSSignerImpl(String privateKeyMultibase, String kid) throws VcDataIntegrityCryptographicSuiteException {
        super(privateKeyMultibase);
        this.kid = kid;
    }

    @Override
    public String getKid() {
        return this.kid;
    }

    @Override
    public JWSAlgorithm getAlgorithm() {
        return JWSAlgorithm.Ed25519;
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(this.getAlgorithm());
    }

    @Override
    public Base64URL sign(JWSHeader jwsHeader, byte[] bytes) throws JOSEException {
        return Base64URL.encode(this.generateSignature(bytes));
    }
}
