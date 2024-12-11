package ch.admin.eid.did.tdw;

import io.ipfs.multibase.Base58;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Base64;

public class Signer {

    byte[] signingKey = new byte[32];
    byte[] verifyingKey = new byte[32];

    /**
     * According to https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020:
     * The publicKeyMultibase property of the verification method MUST be a public key encoded according to [MULTICODEC] and formatted according to [MULTIBASE].
     * The multicodec encoding of a Ed25519 public key is the two-byte prefix 0xed01 followed by the 32-byte public key data.
     *
     * @return
     */
    public String getEd25519VerificationKey2020() {

        byte[] publicKey = this.verifyingKey;
        ByteBuffer buff = ByteBuffer.allocate(34);
        buff.put((byte) 0xed); // Ed25519Pub is a draft code tagged "key" and described by: Ed25519 public key.
        buff.put((byte) 0x01);
        buff.put(Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length));
        return 'z' + Base58.encode(buff.array());
    }

    /*
    public byte[] getSigningKey() {
        return signingKey;
    }
    */

    Signer() {

        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("Ed25519");
            //keyPairGen.initialize(NamedParameterSpec.ED25519, new SecureRandom(secretKey));
            keyPairGen.initialize(NamedParameterSpec.ED25519);

            KeyPair keyPair = keyPairGen.generateKeyPair();

            byte[] privateKey = keyPair.getPrivate().getEncoded();
            this.signingKey = Arrays.copyOfRange(privateKey, privateKey.length - 32, privateKey.length); // the last 32 bytes

            byte[] publicKey = keyPair.getPublic().getEncoded();
            this.verifyingKey = Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length); // the last 32 bytes

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    public Signer(String privateKey, String publicKey) {

        this.signingKey = Hex.decode(new String(Base64.getDecoder().decode(privateKey), StandardCharsets.UTF_8));
        this.verifyingKey = Hex.decode(new String(Base64.getDecoder().decode(publicKey), StandardCharsets.UTF_8));
    }

    public Signer(InputStream jksFile, String password, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(jksFile, password.toCharArray()); // java.io.IOException: keystore password was incorrect

        //var entryPassword = new KeyStore.PasswordProtection(password.toCharArray());
        //KeyStore.Entry keyEntry = keyStore.getEntry(alias, entryPassword);

        var key = keyStore.getKey(alias, password.toCharArray()); // 34 bytes, may return null if the given alias does not exist or does not identify a key-related entry
        /*
        if key == null {
            throw
        }
         */
        byte[] privateKey = key.getEncoded(); // 48 bytes
        this.signingKey = Arrays.copyOfRange(privateKey, privateKey.length - 32, privateKey.length); // the last 32 bytes

        var cert = keyStore.getCertificate(alias); // may return null if the given alias does not exist or does not contain a certificate
        /*
        if cert == null {
            throw
        }
         */
        byte[] publicKey = cert.getPublicKey().getEncoded(); // 44 bytes
        this.verifyingKey = Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length); // the last 32 bytes
    }

    public Signer(File privatePemFile, File publicPemFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        byte[] privatePemBytes = PemUtils.parsePEMFile(privatePemFile);
        PrivateKey privKey = PemUtils.getPrivateKeyEd25519(privatePemBytes);
        byte[] privateKey = privKey.getEncoded(); // 48 bytes
        this.signingKey = Arrays.copyOfRange(privateKey, privateKey.length - 32, privateKey.length); // the last 32 bytes

        byte[] publicPemBytes = PemUtils.parsePEMFile(publicPemFile);
        PublicKey pubKey = PemUtils.getPublicKeyEd25519(publicPemBytes);
        byte[] publicKey = pubKey.getEncoded(); // 44 bytes
        this.verifyingKey = Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length); // the last 32 bytes
    }

    byte[] sign(String message) {

        byte[] msg = message.getBytes(StandardCharsets.UTF_8);

        Ed25519PrivateKeyParameters secretKeyParameters = new Ed25519PrivateKeyParameters(this.signingKey, 0);
        var signer = new Ed25519Signer();
        signer.init(true, secretKeyParameters);
        signer.update(msg, 0, msg.length);

        return signer.generateSignature();
    }

    boolean verify(String message, byte[] signature) {

        Ed25519PublicKeyParameters publicKeyParameters = new Ed25519PublicKeyParameters(this.verifyingKey, 0);
        var verifier = new Ed25519Signer();
        verifier.init(false, publicKeyParameters);
        byte[] msg = message.getBytes(StandardCharsets.UTF_8);
        verifier.update(msg, 0, msg.length);

        return verifier.verifySignature(signature);

    }
}
