package ch.admin.bj.swiyu.didtoolbox;

import com.nimbusds.jose.JWSAlgorithm;

import java.util.Set;

/**
 * Intended for unit testing purposes only.
 */
class UnsafeEd25519ProofOfPossessionJWSSignerImpl extends UnsafeEd25519VerificationMethodKeyProviderImpl implements ProofOfPossessionJWSSigner {

    UnsafeEd25519ProofOfPossessionJWSSignerImpl(String privateKeyMultibase, String publicKeyMultibase) {
        super(privateKeyMultibase, publicKeyMultibase);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.Ed25519);
    }
}
