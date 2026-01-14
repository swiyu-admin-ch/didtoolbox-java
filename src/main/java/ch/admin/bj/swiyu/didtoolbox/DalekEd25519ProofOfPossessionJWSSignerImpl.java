package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.did_sidekicks.DidSidekicksException;
import com.nimbusds.jose.JWSAlgorithm;

import java.io.File;
import java.util.Set;

/**
 * This {@link ProofOfPossessionJWSSigner} implementation builds on top of {@link DalekEd25519VerificationMethodKeyProviderImpl}
 * aiming at reusing the extensive key loading facilities from the base class.
 * <p>
 * To be used in conjunction with {@link ProofOfPossessionCreator#ProofOfPossessionCreator(ProofOfPossessionJWSSigner)}.
 */
public class DalekEd25519ProofOfPossessionJWSSignerImpl extends DalekEd25519VerificationMethodKeyProviderImpl implements ProofOfPossessionJWSSigner {

    /**
     * @see DalekEd25519VerificationMethodKeyProviderImpl#DalekEd25519VerificationMethodKeyProviderImpl(File)
     */
    public DalekEd25519ProofOfPossessionJWSSignerImpl(File pkcs8PemFile) throws DidSidekicksException {
        super(pkcs8PemFile);
    }

    /**
     * @see DalekEd25519VerificationMethodKeyProviderImpl#DalekEd25519VerificationMethodKeyProviderImpl(String)
     */
    public DalekEd25519ProofOfPossessionJWSSignerImpl(String pkcs8PemFile) throws DidSidekicksException {
        super(pkcs8PemFile);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.Ed25519);
    }
}
