package ch.admin.bj.swiyu.didtoolbox;

import io.ipfs.multibase.Base58;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Intended for unit testing purposes only.
 */
public class UnsafeEd25519VerificationMethodKeyProviderImpl extends Ed25519VerificationMethodKeyProviderImpl {

    byte[] signingKey;
    byte[] verifyingKey;

    private UnsafeEd25519VerificationMethodKeyProviderImpl() {
    }

    /**
     * Yet another {@link UnsafeEd25519VerificationMethodKeyProviderImpl} constructor accepting keys in multibase base58btc format, e.g.
     * <p>
     * {@snippet lang = JSON:
     *     {
     *         "publicKeyMultibase": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
     *         "secretKeyMultibase": "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
     *     }
     *}
     * <p>
     * CAUTION Intended for testing purposes ONLY, hence its visibility.
     * <p>
     * CAUTION It is assumed the keys do really match. Otherwise, {@link RuntimeException} is thrown.
     *
     * @param privateKeyMultibase the base58-encoded string to decode as private Ed25519 key
     * @param publicKeyMultibase  the base58-encoded string to decode as public Ed25519 key
     */
    public UnsafeEd25519VerificationMethodKeyProviderImpl(String privateKeyMultibase, String publicKeyMultibase) {

        var signingKey = Base58.decode(privateKeyMultibase.substring(1));
        var verifyingKey = Base58.decode(publicKeyMultibase.substring(1));

        ByteBuffer buff = ByteBuffer.allocate(32);
        buff.put(Arrays.copyOfRange(signingKey, signingKey.length - 32, signingKey.length));
        this.signingKey = buff.array();

        buff = ByteBuffer.allocate(32);
        buff.put(Arrays.copyOfRange(verifyingKey, verifyingKey.length - 32, verifyingKey.length));
        this.verifyingKey = buff.array();

        //var pubKey = Ed25519Utils.toJavaSecurityPublicKey(this.verifyingKey);
        // CAUTION There is no known way to set this.keyPair here
        //this.keyPair = new KeyPair(pubKey, privKey);

        sanityCheck();
    }

    /**
     * This {@link VerificationMethodKeyProvider} interface method implementation is done w.r.t.
     * <a href="https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020">Ed25519verificationkey2020</a>:
     * <pre>
     * The publicKeyMultibase property of the verification method MUST be a public key encoded according to [MULTICODEC] and formatted according to [MULTIBASE].
     * The multicodec encoding of a Ed25519 public key is the two-byte prefix 0xed01 followed by the 32-byte public key data.
     * </pre>
     *
     * @return public verification key in multibase format.
     */
    public String getVerificationKeyMultibase() {

        return Ed25519Utils.encodeMultibase(this.verifyingKey);
    }

    /**
     * The {@link VerificationMethodKeyProvider} interface method implementation using Ed25519 algorithm.
     *
     * @param message to sign
     * @return signed message
     */
    public byte[] generateSignature(byte[] message) {

        // may throw java.lang.IllegalArgumentException: invalid public key
        Ed25519PrivateKeyParameters secretKeyParameters = new Ed25519PrivateKeyParameters(this.signingKey, 0);
        var signer = new Ed25519Signer();
        signer.init(true, secretKeyParameters);
        signer.update(message, 0, message.length);

        return signer.generateSignature();
    }

    boolean verify(byte[] message, byte[] signature) {

        // may throw java.lang.IllegalArgumentException: invalid public key
        Ed25519PublicKeyParameters publicKeyParameters = new Ed25519PublicKeyParameters(this.verifyingKey, 0);
        var verifier = new Ed25519Signer();
        verifier.init(false, publicKeyParameters);
        verifier.update(message, 0, message.length);

        return verifier.verifySignature(signature);
    }
}
