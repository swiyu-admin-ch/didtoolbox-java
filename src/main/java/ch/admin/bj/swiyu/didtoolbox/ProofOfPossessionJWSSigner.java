package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;

/**
 * Built on top of both {@link VcDataIntegrityCryptographicSuite} and {@link JWSSigner},
 * its main purpose is describing the minimal requirements to meet in order to be able to sign PoP JWTs.
 * <p>
 * Its default signing ability comes from the base interface.
 */
public interface ProofOfPossessionJWSSigner extends JWSSigner {

    @Override
    default JCAContext getJCAContext() {
        return null;
    }

    public String getKid();

    public JWSAlgorithm getAlgorithm();
}
