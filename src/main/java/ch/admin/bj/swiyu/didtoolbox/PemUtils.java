package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.Ed25519VerifyingKey;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

@SuppressWarnings({"PMD.TooManyMethods"})
public final class PemUtils {

    private PemUtils() {
    }

    /**
     * Loads a PEM key from the supplied file.
     *
     * @param pemFile to read PEM key from
     * @return the PEM key as byte array
     * @throws FileNotFoundException in case of inappropriate {@code pemFile} parameter value
     * @throws IOException           in case of a parse error
     */
    public static byte[] readPEMFile(File pemFile) throws IOException {

        if (!pemFile.isFile()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }

        return readPemObject(Files.newBufferedReader(pemFile.toPath()));
    }

    static KeyPair parsePemKeyPairFile(File pemFile) throws IOException {

        if (!pemFile.isFile()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }

        return parsePemKeyPair(Files.newBufferedReader(pemFile.toPath()));
    }

    static byte[] readPemObject(Reader pemKeyReader) throws IOException {
        PemReader reader = new PemReader(pemKeyReader);
        PemObject pemObject = reader.readPemObject();
        byte[] content = pemObject.getContent();
        reader.close();
        return content;
    }

    static KeyPair parsePemKeyPair(Reader pemKeyPairReader) throws IOException {
        final PEMParser parser = new PEMParser(pemKeyPairReader);
        var pemObj = parser.readObject();

        // if EC private key given, it arrives here as a keypair
        if (pemObj instanceof PEMKeyPair) {
            return new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) pemObj);
        }

        throw new IllegalArgumentException("The supplied reader features no PEM-encoded key pair");
    }

    static PrivateKey parsePemPrivateKey(Reader pemPrivateKeyReader) throws IOException {
        final PEMParser parser = new PEMParser(pemPrivateKeyReader);
        var pemObj = parser.readObject();

        if (pemObj instanceof PrivateKeyInfo) {
            return new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) pemObj);
        }

        throw new IllegalArgumentException("The supplied reader features no PEM-encoded private key");
    }

    static PublicKey parsePemPublicKey(Reader pemPublicKeyReader) throws IOException {
        final PEMParser parser = new PEMParser(pemPublicKeyReader);
        var pemObj = parser.readObject();

        if (pemObj instanceof SubjectPublicKeyInfo) {
            return new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) pemObj);
        }

        throw new IllegalArgumentException("The supplied reader features no PEM-encoded public key");
    }

    public static String readEd25519PublicKeyPemFileToMultibase(Path publicKeyPemFile) throws DidSidekicksException {

        try (var publicKey = Ed25519VerifyingKey.Companion.readPublicKeyPemFile(publicKeyPemFile.toString())) {
            return publicKey.toMultibase();
        }
    }

    static String fromEd25519PublicKeyPemToMultibase(String pemPublicKey) throws DidSidekicksException {

        try (var publicKey = Ed25519VerifyingKey.Companion.fromPublicKeyPem(pemPublicKey)) {
            return publicKey.toMultibase();
        }
    }
}