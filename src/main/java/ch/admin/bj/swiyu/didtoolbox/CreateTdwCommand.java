package ch.admin.bj.swiyu.didtoolbox;

import com.beust.jcommander.*;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

@Parameters(
        commandNames = {"create"},
        commandDescription = "Create a did:tdw DID Document. Optionally sign the initial log entry if a private key is provided"
)
class CreateTdwCommand {

    @Parameter(names = {"--help", "-h"},
            description = "Display help for the DID toolbox 'create' command",
            help = true)
    boolean help;

    @Parameter(names = {"--domain", "-d"},
            description = "The domain for the DID (e.g. example.com)",
            required = true)
    String domain;

    @Parameter(names = {"--path", "-p"},
            description = "Path segment for the DID (e.g. UUID/GUID)")
    //,required = true)
    String path;

    /*
    static class OutputDirParameterConverter implements IStringConverter<File> {
        @Override
        public File convert(String value) {
            return new File(value);
        }
    }

    public static class OutputDirParameterValidator implements IParameterValidator {
        @Override
        public void validate(String name, String value) throws ParameterException {
            File dir = new File(value);
            if (dir.exists() && !dir.isDirectory()) {
                throw new ParameterException("Parameter " + name + " should be a directory, not a file (found " + value + ")");
            }
        }
    }

    @Parameter(names = {"--key-pair-output-dir", "-o"},
            description = "The directory to store the generated key pair (both in PEM Format), in case no external keys are supplied. Otherwise, ignored",
            converter = OutputDirParameterConverter.class,
            validateWith = OutputDirParameterValidator.class)
    File outputDir;
     */

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

    @Parameter(names = {"--assert", "-a"},
            description = "An assertion method (comma-separated) parameters: a key name as well as a JWKS file containing Ed25519 public/verifying key, as defined by DIDs v1.0 (https://www.w3.org/TR/did-core/#assertion)",
            listConverter = VerificationMethodParametersConverter.class,
            validateWith = VerificationMethodKeyParametersValidator.class,
            variableArity = true)
    List<VerificationMethodParameters> assertionMethodKeys;

    @Parameter(names = {"--auth", "-t"},
            description = "An authentication method (comma-separated) parameters: a key name as well as a JWKS file containing Ed25519 public/verifying key, as defined by DIDs v1.0 (https://www.w3.org/TR/did-core/#authentication)",
            listConverter = VerificationMethodParametersConverter.class,
            validateWith = VerificationMethodKeyParametersValidator.class,
            variableArity = true)
    List<VerificationMethodParameters> authenticationKeys;

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

    static class VerificationMethodParameters {

        String key;
        String jwk;

        public VerificationMethodParameters(String key, String jwk) {
            this.key = key;
            this.jwk = jwk;
        }
    }

    static class VerificationMethodParametersConverter implements IStringConverter<List<VerificationMethodParameters>> {
        @Override
        public List<VerificationMethodParameters> convert(String value) {
            String[] splitted = value.split(",");
            List<VerificationMethodParameters> fileList = new ArrayList<>();
            if (splitted.length == 2) {

                String kid = splitted[0];

                String jwk = null;
                try {

                    jwk = JwkUtils.load(new File(splitted[1]), kid);

                } catch (IOException | ParseException e) {
                    throw new RuntimeException(e);
                }

                fileList.add(new VerificationMethodParameters(kid, jwk));
            }

            return fileList;
        }
    }

    public static class VerificationMethodKeyParametersValidator implements IParameterValidator {
        @Override
        public void validate(String name, String value) throws ParameterException {
            String[] splitted = value.split(",");
            if (splitted.length != 2) {
                throw new ParameterException("Option " + name + " should supply a comma-separated list (in format key-name,public-key-file (Ed25519 public/verifying key in JWKS format)) (found " + value + ")");
            }

            String kid = splitted[0];
            String jwkFile = splitted[1];
            File f = new File(jwkFile);
            if (!f.exists() || !f.isFile()) {
                throw new ParameterException("A public key file (" + jwkFile + ") supplied by " + name + " option must be a regular file containing public/verifying key in JWKS format (found " + jwkFile + ")");
            }

            try {
                JwkUtils.load(f, kid);
            } catch (IOException | ParseException e) {
                throw new ParameterException("A public key file (" + jwkFile + ") supplied by " + name + " option must contain an Ed25519 public/verifying key in JWKS format: " + e.getLocalizedMessage());
            }
        }
    }

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
