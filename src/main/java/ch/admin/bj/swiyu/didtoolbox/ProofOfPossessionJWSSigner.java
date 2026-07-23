package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
    default JCAContext getJCAContext() {
        return null;
    }

    @Override
    default Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(this.getAlgorithm());
    }

    String getKid();

    JWSAlgorithm getAlgorithm();

    static ProofOfPossessionJWSSigner of(Path path, String kid) throws IOException, VcDataIntegrityCryptographicSuiteException {
        try {
            var keyPair = PemUtils.parsePemKeyPair(Files.newBufferedReader(path));
            if (keyPair.getPublic() instanceof ECPublicKey) {
                return new EcP256ProofOfPossessionJWSSigner(keyPair, kid);
            }
        } catch (IllegalArgumentException ignore) {
        }
        var signer = new EdDsaJcs2022JWSSigner(path);
        return of(signer, kid, JWSAlgorithm.EdDSA);
    }

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
        };
    }

}
