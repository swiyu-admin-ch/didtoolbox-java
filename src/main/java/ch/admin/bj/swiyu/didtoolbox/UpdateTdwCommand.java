package ch.admin.bj.swiyu.didtoolbox;

import com.beust.jcommander.*;

import java.io.File;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

@Parameters(
        commandNames = {"update"},
        commandDescription = "Update a did:tdw DID log"
)
class UpdateTdwCommand {

    @Parameter(names = {"--help", "-h"},
            description = "Display help for the DID toolbox 'update' command",
            help = true)
    boolean help;

    static class DidLogFileParameterConverter implements IStringConverter<File> {
        @Override
        public File convert(String value) {
            return new File(value);
        }
    }

    public static class DidLogFileParameterValidator implements IParameterValidator {
        @Override
        public void validate(String name, String value) throws ParameterException {
            File didLogFile = new File(value);
            if (!didLogFile.isFile() || !didLogFile.exists()) {
                throw new ParameterException("Parameter " + name + " should be a regular file containing a valid did:tdw DID log (found " + value + ")");
            }
        }
    }

    @Parameter(names = {"--did-log-file", "-d"},
            description = "The file containing a valid did:tdw DID log to update",
            converter = DidLogFileParameterConverter.class,
            validateWith = DidLogFileParameterValidator.class,
            required = true)
    File didLogFile;

    @Parameter(names = {"--signing-key-file", "-s"},
            description = "The ed25519 private key file corresponding to the public key, required to sign and output the updated DID log entry. In PEM Format",
            converter = CreateTdwCommand.PemFileParameterConverter.class,
            validateWith = CreateTdwCommand.PemFileParameterValidator.class,
            required = true)
    File signingKeyPemFile;

    @Parameter(names = {"--verifying-key-file", "-v"},
            description = "The ed25519 public key file for the DID Document’s verification method. In PEM format",
            converter = CreateTdwCommand.PemFileParameterConverter.class,
            validateWith = CreateTdwCommand.PemFileParameterValidator.class,
            required = true)
    File verifyingKeyPemFile;

    @Parameter(names = {"--jks-file", "-j"},
            description = "Java KeyStore (PKCS12) file to read the (signing/verifying) keys from",
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
            description = "An assertion method (comma-separated) parameters: a key name as well as a PEM file containing EC P-256 public/verifying key",
            listConverter = VerificationMethodParametersConverter.class,
            validateWith = VerificationMethodKeyParametersValidator.class,
            variableArity = true)
    List<VerificationMethodParameters> assertionMethodKeys;

    @Parameter(names = {"--auth", "-t"},
            description = "An authentication method (comma-separated) parameters: a key name as well as a PEM file containing EC P-256 public/verifying key",
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

                    jwk = JwkUtils.loadECPublicJWKasJSON(new File(splitted[1]), kid);

                } catch (IOException | InvalidKeySpecException e) {
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
                throw new ParameterException("Option " + name + " should supply a comma-separated list (in format key-name,public-key-file (EC P-256 public/verifying key in PEM format)) (found " + value + ")");
            }

            String kid = splitted[0];
            String jwkFile = splitted[1];
            File f = new File(jwkFile);
            if (!f.exists() || !f.isFile()) {
                throw new ParameterException("A public key file (" + jwkFile + ") supplied by " + name + " option must be a regular file containing EC P-256 public/verifying key in PEM format (found " + jwkFile + ")");
            }

            try {
                JwkUtils.loadECPublicJWKasJSON(f, kid);
            } catch (IOException | InvalidKeySpecException e) {
                throw new ParameterException("A public key file (" + jwkFile + ") supplied by " + name + " option must contain an EC P-256 public/verifying key in PEM format: " + e.getLocalizedMessage());
            }
        }
    }
}
