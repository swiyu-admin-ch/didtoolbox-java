package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.did_sidekicks.*;
import com.google.gson.JsonElement;
import io.ipfs.multibase.Base58;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.io.File;
import java.net.URL;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * The {@link DalekEd25519VerificationMethodKeyProviderImpl} class is a {@link VerificationMethodKeyProvider} implementation
 * used to generate Ed25519 key pairs (or loading them from the file system).
 * Such key pair is then used for the purpose of DID (<a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a>
 * or <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>) log creation.
 * Furthermore, it also plays an essential role while <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">creating data integrity proof</a>.
 * <p>
 * Instead of relying on standard {@link java.security} package (in conjunction with some JCE provider like Bouncy Castle),
 * this particular implementation is built on top of
 * <a href="https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek">Dalek elliptic curve cryptography</a>,
 * a fast end efficient Rust implementation of ed25519 key generation, signing, and verification.
 * <p>
 * It is predominantly intended to be used within a:
 * <ul>
 * <li> {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext.DidLogCreatorContextBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} method
 * (prior to a {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext#create(URL)} call)</li>
 * <li>{@link ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext.DidLogUpdaterContextBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} method
 * (prior to a {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext#update(String)} call).</li>
 * </ul>
 * <p>
 * Thanks to the following constructor(s), it is also capable of loading an already existing key material from the file system:
 * <ul>
 * <li>{@link DalekEd25519VerificationMethodKeyProviderImpl#DalekEd25519VerificationMethodKeyProviderImpl(File)} for loading the update (Ed25519) key from
 * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> files</li>
 * </ul>
 */
public class DalekEd25519VerificationMethodKeyProviderImpl extends Ed25519VerificationMethodKeyProviderImpl {

    protected Ed25519SigningKey signingKey;
    protected EddsaJcs2022Cryptosuite cryptoSuite;

    public DalekEd25519VerificationMethodKeyProviderImpl() {
        signingKey = Ed25519SigningKey.Companion.generate();
        cryptoSuite = EddsaJcs2022Cryptosuite.Companion.fromSigningKey(signingKey);
    }

    /**
     * The <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> file based {@link DalekEd25519VerificationMethodKeyProviderImpl} constructor.
     * <p>
     *
     * @param pkcs8PemFile file to load a private Ed25519 key from. It is assumed to be encoded according to the PKCS #8 standard.
     * @throws DidSidekicksException if any of the given key specifications is inappropriate for its key factory to produce a key.
     */
    public DalekEd25519VerificationMethodKeyProviderImpl(File pkcs8PemFile) throws DidSidekicksException {
        signingKey = Ed25519SigningKey.Companion.readPkcs8PemFile(pkcs8PemFile.toPath().toString());
        cryptoSuite = EddsaJcs2022Cryptosuite.Companion.fromSigningKey(signingKey);
    }

    /**
     * Yet another constructor accepting keys in multibase base58btc format, e.g.
     * <p>
     * {@snippet lang = JSON:
     *     {
     *         "publicKeyMultibase": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
     *         "secretKeyMultibase": "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
     *     }
     *}
     *
     * @param secretKeyMultibase the base58-encoded string to decode as private Ed25519 key
     */
    public DalekEd25519VerificationMethodKeyProviderImpl(String secretKeyMultibase) throws DidSidekicksException {
        signingKey = Ed25519SigningKey.Companion.fromMultibase(secretKeyMultibase);
        cryptoSuite = EddsaJcs2022Cryptosuite.Companion.fromSigningKey(signingKey);
    }

    /**
     * CAUTION The method does not ensure that the private key file access is restricted to the current user only.
     *
     * @param pkcs8PemFile to store the key
     * @throws DidSidekicksException
     */
    void writePkcs8PemFile(String pkcs8PemFile) throws DidSidekicksException {
        signingKey.writePkcs8PemFile(pkcs8PemFile);
    }

    /**
     * @param publicKeyPemFile to store the key
     * @throws DidSidekicksException
     */
    public void writePublicKeyAsPem(String publicKeyPemFile) throws DidSidekicksException {
        signingKey.getVerifyingKey().writePublicKeyPemFile(publicKeyPemFile);
    }

    /**
     * This {@link VerificationMethodKeyProvider} interface method implementation is done w.r.t.
     * <a href="https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020">Ed25519verificationkey2020</a>:
     * <pre>
     * The publicKeyMultibase property of the verification method MUST be a public key encoded according to [MULTICODEC] and formatted according to [MULTIBASE].
     * The multicodec encoding of an Ed25519 public key is the two-byte prefix 0xed01 followed by the 32-byte public key data.
     * </pre>
     *
     * @return public verification key in multibase format.
     */
    @Override
    public String getVerificationKeyMultibase() {
        return signingKey.getVerifyingKey().toMultibase();
    }

    /**
     * The {@link VerificationMethodKeyProvider} interface method implementation using Ed25519 algorithm.
     *
     * @param message to sign
     * @return signed message
     */
    @Override
    public byte[] generateSignature(byte[] message) {
        /* TODO Call this.signingKey.sign() method, instead of relying on org.bouncycastle.crypto.* classes
        return Base58.decode(this.signingKey.sign(StringUtils.newStringUtf8(message)).toMultibase().substring(1));
         */

        // may throw java.lang.IllegalArgumentException: invalid public key
        var secretKeyParameters = new Ed25519PrivateKeyParameters(
                Ed25519Utils.decodePrivateKeyMultibase(this.signingKey.toMultibase()), 0);
        var signer = new Ed25519Signer();
        signer.init(true, secretKeyParameters);
        signer.update(message, 0, message.length);

        return signer.generateSignature();
    }

    /*
    @Override
    public PrivateKey getSigningKey() throws InvalidKeySpecException {
        File privateKeyPemFile = null;
        try {
            privateKeyPemFile = File.createTempFile("myprivatekey", "");
            signingKey.writePkcs8PemFile(privateKeyPemFile.getPath());
            return PemUtils.readPrivateKeyFromFile(privateKeyPemFile.getPath(), "Ed25519");
        } catch (IOException | DidSidekicksException | NoSuchAlgorithmException intolerable) {
            throw new IllegalArgumentException(intolerable);
        } finally {
            if (privateKeyPemFile != null) {
                privateKeyPemFile.deleteOnExit();
            }
        }
    }
     */

    boolean verify(byte[] message, byte[] signature) {

        Ed25519Signature sign;
        try {
            sign = Ed25519Signature.Companion.fromMultibase('z' + Base58.encode(signature));
        } catch (DidSidekicksException e) {
            // may throw ch.admin.eid.did_sidekicks.DidSidekicksException$MultibaseKeyConversionFailed denoting for instance that it:
            // > failed to convert key from multibase format:
            // > the supplied DID document is invalid or contains an argument which isn't part of the DID specification/recommendation:
            // > buffer provided to decode base58 encoded string into was too small
            throw new IllegalArgumentException(e);
        }

        try {
            this.signingKey.getVerifyingKey().verifyStrict(new String(message), sign);
        } catch (DidSidekicksException e) {
            return false;
        }

        return true;

        /*
        // may throw java.lang.IllegalArgumentException: invalid public key
        Ed25519PublicKeyParameters publicKeyParameters = new Ed25519PublicKeyParameters(
                Ed25519Utils.decodePublicKeyMultibase(this.signingKey.getVerifyingKey().toMultibase()), 0);
        var verifier = new Ed25519Signer();
        verifier.init(false, publicKeyParameters);
        verifier.update(message, 0, message.length);

        return verifier.verifySignature(signature);
         */
    }

    public String addEddsaJcs2022DataIntegrityProof(JsonElement unsecuredDocument,
                                                    String challenge,
                                                    String proofPurpose,
                                                    ZonedDateTime dateTime)
            throws DidSidekicksException {

        var verifyingKeyMultibase = this.signingKey.getVerifyingKey().toMultibase();

        // If unsecuredDocument.@context is present, set proof.@context to unsecuredDocument.@context.
        var ctx = unsecuredDocument.getAsJsonObject().get("@context");
        List<String> context = new ArrayList<>();
        if (ctx != null && ctx.isJsonArray()) {
            ctx.getAsJsonArray().forEach(jsonElement -> {
                context.add(jsonElement.getAsString());
            });
        }

        var securedDoc = this.cryptoSuite.addProof(
                unsecuredDocument.toString(),
                CryptoSuiteProofOptions.Companion.newEddsaJcs2022(
                        DateTimeFormatter.ISO_INSTANT.format(dateTime.truncatedTo(ChronoUnit.SECONDS)),
                        "did:key:" + verifyingKeyMultibase + '#' + verifyingKeyMultibase,
                        proofPurpose,
                        context,
                        challenge
                )
        );

        /*
        // sanity check
        var proof = JsonParser.parseString(securedDoc).getAsJsonObject().get("proof");
        this.cryptoSuite.verifyProof( // may throw DidSidekicksException
                DataIntegrityProof.Companion.fromJsonString(proof.toString()),
                JCSHasher.hashAsHex(unsecuredDocument)
        );
         */

        return securedDoc;
    }
}
