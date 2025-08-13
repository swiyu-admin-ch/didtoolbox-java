package ch.admin.bj.swiyu.didtoolbox;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;

/**
 * Built on top of both {@link VerificationMethodKeyProvider} and {@link JWSSigner},
 * its main purpose is describing the minimal requirements to meet in order to be able to sign PoP JWTs.
 * <p>
 * Its default signing ability comes from the base interface.
 */
public interface ProofOfPossessionJWSSigner extends VerificationMethodKeyProvider, JWSSigner {

    @Override
    default Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        return Base64URL.encode(generateSignature(signingInput));
    }

    @Override
    default JCAContext getJCAContext() {
        return null;
    }
}
