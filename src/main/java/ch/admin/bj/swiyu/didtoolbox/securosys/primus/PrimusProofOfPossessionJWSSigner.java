package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

import ch.admin.bj.swiyu.didtoolbox.ProofOfPossessionJWSSigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Set;

public class PrimusProofOfPossessionJWSSigner implements ProofOfPossessionJWSSigner {
    private final String kid;
    private final KeyPair keyPair;
    private final Provider provider;

    public PrimusProofOfPossessionJWSSigner(PrimusKeyStoreLoader primus, String alias, String password, String kid) throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException {
        this.kid = kid;
        this.keyPair = primus.loadKeyPair(alias, password);
        this.provider = primus.getKeyStore().getProvider();
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
        try {
            var signer = Signature.getInstance(this.getAlgorithm().toString(), provider);
            signer.initSign(keyPair.getPrivate());
            signer.update("message".getBytes(StandardCharsets.UTF_8));
            return Base64URL.encode(signer.sign());
        } catch (InvalidKeyException  | NoSuchAlgorithmException | SignatureException e) {
            // TODO@MP
            throw new JOSEException(e);
        }
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(this.getAlgorithm());
    }
}
