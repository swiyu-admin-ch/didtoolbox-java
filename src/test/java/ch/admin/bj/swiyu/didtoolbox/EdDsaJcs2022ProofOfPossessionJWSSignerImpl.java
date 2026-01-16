package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.JWSAlgorithm;

import java.util.Set;

/**
 * Intended for unit testing purposes only.
 */
//@SuppressWarnings("PMD")
class EdDsaJcs2022ProofOfPossessionJWSSignerImpl extends EdDsaJcs2022VcDataIntegrityCryptographicSuite implements ProofOfPossessionJWSSigner {

    EdDsaJcs2022ProofOfPossessionJWSSignerImpl(String privateKeyMultibase) throws VcDataIntegrityCryptographicSuiteException {
        super(privateKeyMultibase);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.Ed25519);
    }
}
