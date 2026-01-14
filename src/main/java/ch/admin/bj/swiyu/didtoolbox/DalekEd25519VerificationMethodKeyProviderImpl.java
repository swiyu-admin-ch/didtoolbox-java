package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext;
import ch.admin.eid.did_sidekicks.*;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import io.ipfs.multibase.Base58;

import java.io.File;
import java.net.URL;
import java.nio.charset.Charset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

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
 * As any other {@link VerificationMethodKeyProvider} implementation, it is predominantly intended to be used in conjunction with:
 * <ul>
 * <li> {@link DidLogCreatorContext.DidLogCreatorContextBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} method
 * (prior to a {@link DidLogCreatorContext#create(URL)} call)</li>
 * <li>{@link DidLogUpdaterContext.DidLogUpdaterContextBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} method
 * (prior to a {@link DidLogUpdaterContext#update(String)} call).</li>
 * </ul>
 * <p>
 * Thanks to the following constructor(s), it is also capable of loading an already existing key material from the file system:
 * <ul>
 * <li>{@link DalekEd25519VerificationMethodKeyProviderImpl#DalekEd25519VerificationMethodKeyProviderImpl(File)} for loading the update (Ed25519) key from
 * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> files</li>
 * </ul>
 */
public class DalekEd25519VerificationMethodKeyProviderImpl implements VerificationMethodKeyProvider {

    protected Ed25519SigningKey signingKey;
    protected EddsaJcs2022Cryptosuite cryptoSuite;

    /**
     * The empty constructor delivers a fully operational <a href="https://w3c.github.io/vc-di-eddsa/#eddsa-jcs-2022">eddsa-jcs-2022</a> cryptosuite.
     * <p>
     * Both new Ed25519 signing key (as defined in <a href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1">RFC8032 § 5.1.5</a>)
     * as well as a suitable <a href="https://w3c.github.io/vc-di-eddsa/#eddsa-jcs-2022">eddsa-jcs-2022</a> cryptosuite will be generated as well.
     */
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
        signingKey = Ed25519SigningKey.Companion.readPkcs8PemFile(pkcs8PemFile.getPath());
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
     * Write ASN.1 DER-encoded PKCS#8 private key to the given path.
     * <p>
     * CAUTION The method does not ensure that the private key file access is restricted to the current user only.
     *
     * @param pkcs8PemFile to store the key into
     * @throws DidSidekicksException if the writing operation fails
     */
    void writePkcs8PemFile(File pkcs8PemFile) throws DidSidekicksException {
        signingKey.writePkcs8PemFile(pkcs8PemFile.getPath());
    }

    /**
     * Write ASN.1 DER-encoded public key to the given file.
     *
     * @param publicKeyPemFile to store the key into
     * @throws DidSidekicksException if the writing operation fails
     */
    public void writePublicKeyPemFile(File publicKeyPemFile) throws DidSidekicksException {
        signingKey.getVerifyingKey().writePublicKeyPemFile(publicKeyPemFile.getPath());
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

    @SuppressWarnings({"PMD.AvoidThrowingRawExceptionTypes"})
    @Override
    public byte[] generateSignature(byte[] message) {
        try {
            return Base58.decode(this.signingKey.signHex(HexFormat.of().formatHex(message)).toMultibase().substring(1));
        } catch (DidSidekicksException e) {
            // The 'signHex' will never fail as long HexFormat.of().formatHex call ensures the message is supplied as hex-encoded string
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean isKeyMultibaseInSet(Set<String> multibaseEncodedKeys) {
        return multibaseEncodedKeys.contains(this.getVerificationKeyMultibase());
    }

    /**
     * "Strictly" verify a signature on a message with "malleability" in mind, as thoroughly elaborated
     * <a href="https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict">here</a>.
     *
     * @param message   to verify the supplied signature for
     * @param signature multibase-encoded Ed25519 signature on the supplied message
     * @return {@code true} if the signature is valid, otherwise {@code false}.
     */
    boolean verifyStrict(byte[] message, byte[] signature) {

        try (var sign = Ed25519Signature.Companion.fromMultibase('z' + Base58.encode(signature))) {

            try {
                this.signingKey.getVerifyingKey().verifyStrict(new String(message, Charset.defaultCharset()), sign);
            } catch (DidSidekicksException ignore) {
                return false;
            }

        } catch (DidSidekicksException e) {
            // may throw ch.admin.eid.did_sidekicks.DidSidekicksException$MultibaseKeyConversionFailed denoting for instance that it:
            // > failed to convert key from multibase format:
            // > the supplied DID document is invalid or contains an argument which isn't part of the DID specification/recommendation:
            // > buffer provided to decode base58 encoded string into was too small
            throw new IllegalArgumentException(e);
        }

        return true;
    }

    @Override
    public String addEddsaJcs2022DataIntegrityProof(String unsecuredDocument,
                                                    String challenge,
                                                    String proofPurpose,
                                                    ZonedDateTime dateTime)
            throws VerificationMethodKeyProviderException {

        JsonObject unsecuredDocumentJsonObject;
        try {
            unsecuredDocumentJsonObject = JsonParser.parseString(unsecuredDocument).getAsJsonObject();
        } catch (JsonSyntaxException | IllegalStateException ex) {
            throw new VerificationMethodKeyProviderException(ex);
        }

        var verifyingKeyMultibase = this.signingKey.getVerifyingKey().toMultibase();

        // According to https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022:
        // 2) If unsecuredDocument.@context is present, set proof.@context to unsecuredDocument.@context.
        var ctx = unsecuredDocumentJsonObject.get("@context");
        List<String> context = new ArrayList<>();
        if (ctx != null && ctx.isJsonArray()) {
            ctx.getAsJsonArray().forEach(jsonElement -> {
                context.add(jsonElement.getAsString());
            });
        }

        List<String> finalContext = null;
        if (!context.isEmpty()) {
            finalContext = context;
        }

        try {
            return this.cryptoSuite.addProof(
                    unsecuredDocument,
                    CryptoSuiteProofOptions.Companion.newEddsaJcs2022(
                            DateTimeFormatter.ISO_INSTANT.format(dateTime.truncatedTo(ChronoUnit.SECONDS)),
                            "did:key:" + verifyingKeyMultibase + '#' + verifyingKeyMultibase,
                            proofPurpose,
                            finalContext,
                            challenge
                    )
            );

        } catch (DidSidekicksException e) {
            throw new VerificationMethodKeyProviderException(e);
        }
    }
}
