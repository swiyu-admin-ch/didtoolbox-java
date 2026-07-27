package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusEd25519ProofOfPossessionJWSSignerImpl;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreLoader;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

/**
 * Built on top of both {@link VcDataIntegrityCryptographicSuite} and {@link JWSSigner},
 * its main purpose is describing the minimal requirements to meet in order to be able to sign PoP JWTs.
 * <p>
 * Its default signing ability comes from the base interface.
 */
public interface ProofOfPossessionJWSSigner extends JWSSigner {

    @Override
    default Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(this.getAlgorithm());
    }

    /**
     * Returns the KID intended to be stored in the header of the signed JWT as `kid`.
     * @return
     */
    String getKid();

    /**
     * Returns the preferred algorithm to be used for signing.
     * @return
     */
    JWSAlgorithm getAlgorithm();

    /**
     * Returns a {@link ProofOfPossessionJWSSigner} using the key material of the pem for signing.
     * Only P-256 and Ed25519 are supported.
     *
     * @param path to the PEM file containing a private key
     * @param kid  to be included in the JWT header
     * @return
     * @throws IOException    if the file cannot be read
     * @throws JOSEException  if the pem cannot be parsed to P-256
     * @throws VcDataIntegrityCryptographicSuiteException if the file cannot be parsed to Ed25519
     */
    static ProofOfPossessionJWSSigner of(Path path, String kid) throws IOException, VcDataIntegrityCryptographicSuiteException, JOSEException {
        try {
            var keyPair = PemUtils.parsePemKeyPair(Files.newBufferedReader(path));
            if (keyPair.getPublic() instanceof ECPublicKey) {
                return new EcP256ProofOfPossessionJWSSigner(keyPair, kid);
            }
        } catch (IllegalArgumentException ignore) { } // NOPMD: try EdDsa as fallback

        var signer = new EdDsaJcs2022JWSSigner(path);
        return of(signer, kid, JWSAlgorithm.EdDSA);
    }

    /**
     * Relies on Securosys Primus HSM cluster as source for signing.
     *
     * @param primus the HSM cluster
     * @param password to load the key
     * @param alias of the key inside the HSM cluster
     * @param kid of the key inside the JWT
     */
    static ProofOfPossessionJWSSigner of(PrimusKeyStoreLoader primus, String alias, String password, String kid) throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException, JOSEException {
        var pk = (ECPrivateKey) primus.loadKeyPair(alias, password).getPrivate();
        if (pk instanceof ECPrivateKey) {
            var signer = new ECDSASigner(pk);
            signer.getJCAContext().setProvider(primus.getKeyStore().getProvider());
            return of(signer, kid, JWSAlgorithm.ES256);
        } else {
            var signer = new PrimusEd25519ProofOfPossessionJWSSignerImpl(primus, alias, password, kid);
            return of(signer, kid, JWSAlgorithm.EdDSA);
        }
    }

    /**
     * Creates a ProofOfPosessionsJWSSigner using the provided signer, kid, and alg.
     *
     * @param signer
     * @param kid
     * @param alg
     * @return
     */
    static ProofOfPossessionJWSSigner of(JWSSigner signer, String kid, JWSAlgorithm alg) {
        return new ProofOfPossessionJWSSigner(){
            @Override
            public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
                return signer.sign(header, signingInput);
            }

            @Override
            public String getKid() {
                return kid;
            }

            @Override
            public JWSAlgorithm getAlgorithm() {
                return alg;
            }

            @Override
            public JCAContext getJCAContext() {
                return signer.getJCAContext();
            }
        };
    }

}
