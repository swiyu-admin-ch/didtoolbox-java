package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

import ch.admin.bj.swiyu.didtoolbox.ProofOfPossessionCreator;
import ch.admin.bj.swiyu.didtoolbox.ProofOfPossessionJWSSigner;
import com.nimbusds.jose.JWSAlgorithm;

import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.Set;

/**
 * This {@link ProofOfPossessionJWSSigner} implementation builds on top of {@link PrimusEd25519VerificationMethodKeyProviderImpl}
 * aiming at reusing the extensive key loading facilities from the base class.
 * <p>
 * To be used in conjunction with {@link ProofOfPossessionCreator#ProofOfPossessionCreator(ProofOfPossessionJWSSigner)}.
 */
public class PrimusEd25519ProofOfPossessionJWSSignerImpl extends PrimusEd25519VerificationMethodKeyProviderImpl implements ProofOfPossessionJWSSigner {

    /**
     * @see PrimusEd25519VerificationMethodKeyProviderImpl#PrimusEd25519VerificationMethodKeyProviderImpl(PrimusKeyStoreLoader, String, String)
     */
    public PrimusEd25519ProofOfPossessionJWSSignerImpl(PrimusKeyStoreLoader primus, String alias, String password)
            throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException {
        super(primus, alias, password);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.Ed25519);
    }
}
