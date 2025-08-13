package ch.admin.bj.swiyu.didtoolbox;

import com.nimbusds.jose.JWSAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;

/**
 * This {@link ProofOfPossessionJWSSigner} implementation builds on top of {@link Ed25519VerificationMethodKeyProviderImpl}
 * aiming at reusing the extensive key loading facilities from the base class.
 * <p>
 * To be used in conjunction with {@link ProofOfPossessionCreator#ProofOfPossessionCreator(ProofOfPossessionJWSSigner)}.
 */
public class Ed25519ProofOfPossessionJWSSignerImpl extends Ed25519VerificationMethodKeyProviderImpl implements ProofOfPossessionJWSSigner {

    /**
     * @see Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(Reader, Reader)
     */
    public Ed25519ProofOfPossessionJWSSignerImpl(Reader privateKeyReader, Reader publicKeyReader) throws IOException, InvalidKeySpecException {
        super(privateKeyReader, publicKeyReader);
    }

    /**
     * @see Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(InputStream, String, String, String)
     */
    public Ed25519ProofOfPossessionJWSSignerImpl(InputStream jksFile, String password, String alias, String keyPassword)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyException {
        super(jksFile, password, alias, keyPassword);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.Ed25519);
    }
}
