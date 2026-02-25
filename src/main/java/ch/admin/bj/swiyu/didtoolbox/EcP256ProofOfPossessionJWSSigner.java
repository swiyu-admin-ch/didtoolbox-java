package ch.admin.bj.swiyu.didtoolbox;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Date;
import java.util.Set;

public class EcP256ProofOfPossessionJWSSigner implements ProofOfPossessionJWSSigner {
    protected ECKey signingKey;

    public EcP256ProofOfPossessionJWSSigner(String keyId) throws JOSEException {
        this.signingKey = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).keyID(keyId).issueTime(new Date()).generate();
    }

    public EcP256ProofOfPossessionJWSSigner(Path path, String keyId) throws IOException {
        var keyPair = PemUtils.parsePemKeyPair(Files.newBufferedReader(path));
        this.signingKey = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic()).keyID(keyId).privateKey((ECPrivateKey) keyPair.getPrivate()).build();
    }

    @Override
    public String getKid() {
        return this.signingKey.getKeyID();
    }

    @Override
    public JWSAlgorithm getAlgorithm() {
        return JWSAlgorithm.ES256;
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(this.getAlgorithm());
    }

    @Override
    public Base64URL sign(JWSHeader jwsHeader, byte[] bytes) throws JOSEException {
        try {
            return new ECDSASigner(signingKey.toECPrivateKey()).sign(new JWSHeader(JWSAlgorithm.ES256), bytes);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
