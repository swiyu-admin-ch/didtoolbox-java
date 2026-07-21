package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.VerificationMaterial;
import ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod;
import ch.admin.bj.swiyu.didtoolbox.model.VerificationMethodException;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import lombok.NonNull;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.*;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * The {@link JwkUtils} is a simple helper for the purpose of <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">JWKS</a>
 * key pair generation
 */
public final class JwkUtils {

    private JwkUtils() {
    }

    /**
     * Loads a public P-256 key from the specified PEM file and returns its JWK JSON representation
     *
     * @param ecPublicPemFile the P-256 public key in PEM format
     * @param kid             the ID (kid) of the JWK that can be used to match this key.
     *                        A regular case-sensitive string featuring no URIs reserved characters is expected.
     *                        Otherwise, {@link IllegalArgumentException} is thrown
     * @return JSON object string representation of the public JWK
     * @throws IOException             if the file couldn't be read
     * @throws InvalidKeySpecException if the given key specification is inappropriate for the EC key factory to produce a public key
     * @deprecated Use {@link #loadECPublicJWKasJSON(Path, String)} instead
     */
    @Deprecated(since = "1.8.0")
    public static String loadECPublicJWKasJSON(File ecPublicPemFile, String kid) throws IOException, InvalidKeySpecException {
        return loadECPublicJWKasJSON(ecPublicPemFile.toPath(), kid);
    }

    /**
     * Loads a public P-256 key from the specified PEM file and returns its JWK JSON representation
     *
     * @param ecPublicPemPath to file featuring an P-256 public key in PEM format
     * @param kid             the ID (kid) of the JWK that can be used to match this key.
     *                        A regular case-sensitive string featuring no URIs reserved characters is expected.
     *                        Otherwise, {@link IllegalArgumentException} is thrown
     * @return JSON object string representation of the public JWK
     * @throws IOException             if the file couldn't be read
     * @throws InvalidKeySpecException if the given key specification is inappropriate for the EC key factory to produce a public key
     */
    public static String loadECPublicJWKasJSON(Path ecPublicPemPath, String kid) throws IOException {
        if (!Files.isReadable(ecPublicPemPath)) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", ecPublicPemPath));
        }

        if (!kid.matches("[a-zA-Z0-9~._-]+")) {
            throw new IllegalArgumentException(String.format("The supplied key ID (kid) of the JWK '%s' must be a regular case-sensitive string featuring no URIs reserved characters", kid));
        }

        try {
            var jwk = VerificationMaterial.of(kid, ecPublicPemPath);
            return jwk.getPublicKeyJwk();
        } catch (DidSidekicksException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Use generatePublicP256VerificationMaterial instead of this method.
     *
     * Generates a new key pair (in <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">JWKS</a> format)
     * using standard digital signature algorithm
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.4">ECDSA using P-256 curve and SHA-256 hash function</a>.
     * The key pair is exported in
     * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format.
     * Needless to say, the helper ensures the private key file access is restricted to current user only.
     *
     * @param kid            the ID of the JWK, that can be used to match a specific key
     * @param keyPairPemFile the file where a generated key pair will be stored
     *                       (in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format)
     * @param forceOverwrite the flag controlling whether the existing PEM files should be overwritten or not
     * @return a new public EC JWK (in JSON format).
     * @throws IOException if persisting a key pair fails
     */
    @Deprecated(since = "2.3.0")
    public static String generatePublicEC256(String kid, @NonNull File keyPairPemFile, boolean forceOverwrite) throws IOException {
        return generatePublicP256VerificationMethod(kid, keyPairPemFile, forceOverwrite).getVerificationMaterial().getPublicKeyJwk();
    }

    /**
     * Generates a new key pair (in <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">JWKS</a> format)
     * using standard digital signature algorithm
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.4">ECDSA using P-256 curve and SHA-256 hash function</a>.
     * The key pair is exported in
     * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format.
     * Needless to say, the helper ensures the private key file access is restricted to current user only.
     *
     * @param kid            the ID of the JWK, that can be used to match a specific key
     * @param keyPairPemFile the file where a generated key pair will be stored
     *                       (in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format)
     * @param forceOverwrite the flag controlling whether the existing PEM files should be overwritten or not
     * @return VerificationMaterial
     * @throws IOException if persisting a key pair fails
     */
    public static VerificationMethod generatePublicP256VerificationMethod(String kid, @NonNull File keyPairPemFile, boolean forceOverwrite) throws IOException {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }

        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair); // CAUTION The whole key pair is expected to be written here, not only the private key
        }
        String keyPairPem = stringWriter.toString();

        stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair.getPublic());
        }
        String publicKeyPem = stringWriter.toString();

        VerificationMethod verificationMethod;
        try {
            verificationMethod = VerificationMethod.of(VerificationMaterial.of(kid, publicKeyPem));
        } catch (DidSidekicksException | VerificationMethodException | IOException e) {
            throw new IllegalArgumentException(e);
        }

        writePemFilesToDisk(keyPairPemFile, publicKeyPem, keyPairPem, forceOverwrite);

        return verificationMethod;
    }

    /**
     * Generates a new key pair (in <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">JWKS</a> format)
     * using standard digital signature algorithm
     * <a href="https://www.rfc-editor.org/rfc/rfc8032.html#section-5">EDDSA using Ed25519</a>.
     * The key pair is exported in
     * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format.
     * Needless to say, the helper ensures the private key file access is restricted to current user only.
     *
     * @param kid            the ID of the JWK, that can be used to match a specific key
     * @param keyPairPemFile the file where a generated key pair will be stored
     *                       (in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format)
     * @param forceOverwrite the flag controlling whether the existing PEM files should be overwritten or not
     * @return VerificationMaterial
     * @throws IOException if persisting a key pair fails
     */
    public static VerificationMethod generatePublicEd25519VerificationMethod(String kid, File keyPairPemFile, boolean forceOverwrite) throws IOException {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair); // CAUTION The whole key pair is expected to be written here, not only the private key
        }
        String keyPairPem = stringWriter.toString();

        stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair.getPublic());
        }
        String publicKeyPem = stringWriter.toString();

        VerificationMethod verificationMethod;
        try {
            verificationMethod = VerificationMethod.of(VerificationMaterial.of(kid, publicKeyPem));
        } catch (DidSidekicksException | VerificationMethodException | IOException e) {
            throw new IllegalArgumentException(e);
        }

        writePemFilesToDisk(keyPairPemFile, publicKeyPem, keyPairPem, forceOverwrite);

        return verificationMethod;
    }

    /**
     * Writes the contents of privatePem to the provided file and the contents of publicPem to the file with + '.pub'.
     * If one of the files already exists the function will return an IOException, unless forceOverwrite is true.
     * @param keyPairPemFile
     * @param publicPem
     * @param privatePem
     * @param forceOverwrite
     * @throws IOException
     */
    private static void writePemFilesToDisk(File keyPairPemFile, String publicPem, String privatePem, boolean forceOverwrite) throws IOException {
        if (keyPairPemFile.exists() && !forceOverwrite) {
            throw new IOException("The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged: " + keyPairPemFile.getPath());
        }

        var publicKeyFile = Path.of(keyPairPemFile.getPath() + ".pub");
        if (publicKeyFile.toFile().exists() && !forceOverwrite) {
            throw new IOException("Public key file already exists");
        }

        createPrivateFile(keyPairPemFile, forceOverwrite);
        try (Writer w = Files.newBufferedWriter(keyPairPemFile.toPath())) {
            w.write(privatePem);
            w.flush();
        }

        try (var writer = Files.newBufferedWriter(publicKeyFile)) {
            writer.write(publicPem);
            writer.flush();
        }
    }

    /**
     * Wrapper for {@link FilesPrivacy#createPrivateFile(Path, boolean)}
     */
    private static void createPrivateFile(File keyPairPemFile, boolean forceOverwrite) throws IOException {
        try {
            // CAUTION A private key file MUST always be created with appropriate file permissions i.e. with access restricted to the current user only
            FilesPrivacy.createPrivateFile(keyPairPemFile.toPath(), forceOverwrite); // may throw FileAlreadyExistsException, SecurityException etc.
        } catch (DirectoryNotEmptyException | AccessDeniedException ex) {
            // the file must not exist and write access must be already granted
            throw new IllegalArgumentException(ex); // it should be a file, not a directory
        } catch (FileAlreadyExistsException ex) {
            if (!keyPairPemFile.exists()) {
                throw new IllegalArgumentException(ex);
            }
            throw ex;
        } catch (Throwable thr) { // NOPMD AvoidCatchingGenericException
            throw new IOException("The private key PEM file " + keyPairPemFile.getPath() + " could not be (re)created with restricted access due to: " + thr.getMessage(), thr);
        }
    }

}
