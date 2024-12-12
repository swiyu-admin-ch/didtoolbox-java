package ch.admin.bj.swiyu.didtoolbox;

import com.beust.jcommander.*;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Parameters(
        commandNames = {"create"},
        commandDescription = "Create a did:tdw DID Document. Optionally sign the initial log entry if a private key is provided"
)
class CreateTdwCommand {

    @Parameter(names = {"--domain", "-d"},
            description = "The domain for the DID (e.g. example.com)",
            required = true)
    String domain;

    @Parameter(names = {"--path", "-p"},
            description = "Path segment for the DID (e.g. UUID/GUID)")
    String path;

    static class PemFileParameterConverter implements IStringConverter<File> {
        @Override
        public File convert(String value) {
            return new File(value);
        }
    }

    public static class PemFileParameterValidator implements IParameterValidator {
        @Override
        public void validate(String name, String value) throws ParameterException {
            File pemFile = new File(value);
            if (!pemFile.isFile() || !pemFile.exists()) {
                throw new ParameterException("Parameter " + name + " should be a regular file containing key in PEM format (found " + value + ")");
            }
        }
    }

    @Parameter(names = {"--signing-key-file", "-s"},
            description = "The ed25519 private key file corresponding to the public key, required to sign and output the initial DID log entry. In PEM Format",
            converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class)
    File signingKeyPemFile;

    @Parameter(names = {"--verifying-key-file", "-v"},
            description = "The ed25519 public key file for the DID Document’s verification method. In PEM format",
            converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class)
    File verifyingKeyPemFile;

    static class JksFileParameterConverter implements IStringConverter<File> {
        @Override
        public File convert(String value) {
            return new File(value);
        }
    }

    public static class JksFileParameterValidator implements IParameterValidator {
        @Override
        public void validate(String name, String value) throws ParameterException {
            File pemFile = new File(value);
            if (!pemFile.isFile() || !pemFile.exists()) {
                throw new ParameterException("Parameter " + name + " should be a regular file in Java KeyStore (PKCS12) format (found " + value + ")");
            }
        }
    }

    @Parameter(names = {"--jks-file", "-j"},
            description = "Java KeyStore (PKCS12) file to read the keys from",
            converter = JksFileParameterConverter.class,
            validateWith = JksFileParameterValidator.class)
    File jksFile;

    @Parameter(names = {"--jks-password"},
            description = "Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore",
            password = true)
    String jksPassword;

    @Parameter(names = {"--jks-alias"},
            description = "Java KeyStore alias")
    String jksAlias;

    static class AssertionMethodParameters {

        String key;
        String publicKeyMultibase;

        public AssertionMethodParameters(String key, String publicKeyMultibase) {
            this.key = key;
            this.publicKeyMultibase = publicKeyMultibase;
        }
    }

    static class AssertionMethodParametersConverter implements IStringConverter<List<AssertionMethodParameters>> {
        @Override
        public List<AssertionMethodParameters> convert(String value) {
            String[] splitted = value.split(",");
            List<AssertionMethodParameters> fileList = new ArrayList<>();
            if (splitted.length == 2) {

                byte[] publicPemBytes = null;
                PublicKey pubKey;
                try {
                    publicPemBytes = PemUtils.parsePEMFile(new File(splitted[1]));
                    pubKey = PemUtils.getPublicKeyEd25519(publicPemBytes);

                } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                    throw new RuntimeException(e);
                }

                byte[] publicKey = pubKey.getEncoded(); // 44 bytes
                var verifyingKey = Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length); // the last 32 bytes

                fileList.add(new AssertionMethodParameters(splitted[0], Signer.buildEd25519VerificationKey2020(verifyingKey)));
            }
            return fileList;
        }
    }

    public static class AssertionMethodParametersValidator implements IParameterValidator {
        @Override
        public void validate(String name, String value) throws ParameterException {
            String[] splitted = value.split(",");
            if (splitted.length != 2) {
                throw new ParameterException("Option " + name + " should supply a comma-separated list (in format key-name,public-key-file (Ed25519 public/verifying key in PEM format)) (found " + value + ")");
            }

            String pubKeyFile = splitted[1];
            File f = new File(pubKeyFile);
            if (!f.exists() || !f.isFile()) {
                throw new ParameterException("A public key file (" + pubKeyFile + ") supplied by " + name + " option must be a regular file containing public/verifying key in PEM format (found " + pubKeyFile + ")");
            }

            try {
                PemUtils.getPublicKeyEd25519(PemUtils.parsePEMFile(f));
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new ParameterException("A public key file (" + pubKeyFile + ") supplied by " + name + " option must contain an Ed25519 public/verifying key in PEM format: " + e.getLocalizedMessage());
            }
        }
    }

    @Parameter(names = {"--assertion", "-a"},
            description = "An (embedded) assertion method (comma-separated) parameters: a key name as well as a PEM file containing Ed25519 public/verifying key, as defined by DIDs v1.0 (https://www.w3.org/TR/did-core/#assertion)",
            listConverter = AssertionMethodParametersConverter.class,
            validateWith = AssertionMethodParametersValidator.class,
            variableArity = true)
    List<AssertionMethodParameters> assertions;

    /*
    @Parameter(names = "-i")
    private Boolean interactive = false;

    @Parameter
    private List<String> parameters = new ArrayList<>();

    @Parameter(names = {"-v", "--verbose"}, description = "Level of verbosity")
    private Integer verbose = 1;

    @Parameter(names = "--debug", description = "Debug mode")
    private boolean debug = false;
     */
}
