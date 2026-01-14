package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.did_sidekicks.DidSidekicksException;
import com.nimbusds.jose.JWSAlgorithm;

import java.util.Set;

/**
 * Intended for unit testing purposes only.
 */
@SuppressWarnings("PMD")
class DalekEd25519ProofOfPossessionJWSSignerImpl extends DalekEd25519VerificationMethodKeyProviderImpl implements ProofOfPossessionJWSSigner {

    DalekEd25519ProofOfPossessionJWSSignerImpl(String privateKeyMultibase) throws DidSidekicksException {
        super(privateKeyMultibase);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.Ed25519);
    }
}
