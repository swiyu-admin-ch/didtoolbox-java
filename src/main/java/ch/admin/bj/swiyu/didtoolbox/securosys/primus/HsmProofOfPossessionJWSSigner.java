package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

import ch.admin.bj.swiyu.didtoolbox.ProofOfPossessionJWSSigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.util.Set;

/**
 * {@link HsmProofOfPossessionJWSSigner} provides multiple constructors for different HSM providers intended to be used with {@link ch.admin.bj.swiyu.didtoolbox.ProofOfPossessionCreator}.
 */
public class HsmProofOfPossessionJWSSigner implements ProofOfPossessionJWSSigner {
    private final String kid;
    private final JWSSigner signer;

    private HsmProofOfPossessionJWSSigner(JWSSigner signer, String kid) {
        this.kid = kid;
        this.signer = signer;
    }

    /**
     * Relies on Securosys Primus HSM cluster as source for signing.
     *
     * @param primus the HSM cluster
     * @param password to load the key
     * @param alias of the key inside the HSM cluster
     * @param kid of the key inside the JWT
     */
    public static HsmProofOfPossessionJWSSigner newPrimusSigner(PrimusKeyStoreLoader primus, String alias, String password, String kid) throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException, JOSEException {
        var pk = (ECPrivateKey) primus.loadKeyPair(alias, password).getPrivate();
        var signer = new ECDSASigner(pk);
        signer.getJCAContext().setProvider(primus.getKeyStore().getProvider());
        return new HsmProofOfPossessionJWSSigner(signer, kid);
    }

    /**
     * Relies on PKCS11 for signing.
     *
     * @param cfgPath Path to the configuration file
     * @param keystoreSecret
     * @param keyId
     * @param kid of the key inside the JWT
     * @return
     */
    public static HsmProofOfPossessionJWSSigner newPkcs11Signer(String cfgPath, String keystoreSecret, String keyId, String kid) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, JOSEException {
        Provider provider = Security.getProvider("SunPKCS11");
        provider = provider.configure(cfgPath);
        Security.addProvider(provider);
        var hsmKeyStore = KeyStore.getInstance("PKCS11", provider);
        hsmKeyStore.load(null, keystoreSecret.toCharArray());
        var privateKey =  ECKey.load(hsmKeyStore, keyId, keystoreSecret.toCharArray());
        var signer = new ECDSASigner(privateKey);
        return new HsmProofOfPossessionJWSSigner(signer, kid);
    }

    @Override
    public String getKid() {
        return this.kid;
    }

    @Override
    public JWSAlgorithm getAlgorithm() {
        return JWSAlgorithm.ES256;
    }

    @Override
    public Base64URL sign(JWSHeader jwsHeader, byte[] bytes) throws JOSEException {
        return signer.sign(jwsHeader, bytes);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(this.getAlgorithm());
    }
}
