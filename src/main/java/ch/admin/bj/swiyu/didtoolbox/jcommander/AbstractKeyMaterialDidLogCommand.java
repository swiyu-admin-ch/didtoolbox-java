package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.FilesPrivacy;
import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.PemFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.VerificationMethodKeyParametersValidator;
import ch.admin.bj.swiyu.didtoolbox.model.CryptographicAlgorithm;
import ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod;
import ch.admin.bj.swiyu.didtoolbox.model.VerificationMethodException;
import com.beust.jcommander.Parameter;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import static ch.admin.bj.swiyu.didtoolbox.jcommander.CommandParameterNames.*;

/**
 * The base class for all Command classes in the package that require supply of a key material.
 */
public class AbstractKeyMaterialDidLogCommand extends AbstractDidLogCommandBase {

    protected AbstractKeyMaterialDidLogCommand() {
    }

    @Override
    String getCommandName() {
        return "";
    }

    @Parameter(names = {PARAM_NAME_LONG_VERIFYING_KEY_FILES, PARAM_NAME_SHORT_VERIFYING_KEY_FILES},
            description = "One or more Ed25519 public key file(s) for the DID Document’s verification method. In PEM format.",
            listConverter = PemFileParameterListConverter.class,
            validateWith = PemFileParameterValidator.class,
            variableArity = true)
    public Set<File> verifyingKeyPemFiles = new HashSet<>();

    @Parameter(names = {PARAM_NAME_LONG_NEXT_VERIFYING_KEY_FILES, PARAM_NAME_SHORT_NEXT_VERIFYING_KEY_FILES},
            description = "One or more Ed25519 public key file(s) to be used as 'pre-rotation' keys. In PEM format. Using the CLI option activates 'key pre-rotation'. Analogously, deactivating 'key pre-rotation' goes simply by omitting this option altogether",
            listConverter = PemFileParameterListConverter.class,
            validateWith = PemFileParameterValidator.class,
            variableArity = true)
    public Set<File> nextVerifyingKeyPemFiles = new HashSet<>();

    @Parameter(names = {PARAM_NAME_LONG_GENERATE_NEXT_VERIFYING_KEY, PARAM_NAME_SHORT_GENERATE_NEXT_VERIFYING_KEY},
            description = "Generates a new Ed25519 key pair to be used as the next signing key. The generated key pair is stored in the `.didtoolbox` directory. CAUTION: using `-f` can override existing keys in the directory, make sure to back them up. Cannot be used together with the generate verifying key next flag ('-gv')")
    public boolean shouldGenerateNextVerifyingKeyPem;

    @Parameter(names = {PARAM_NAME_LONG_ASSERTION_METHOD_KEYS, PARAM_NAME_SHORT_ASSERTION_METHOD_KEYS},
            description = "One or more assertion method parameter(s) - each parameter consists of a (comma-separated) key name and a PEM file containing an EC P-256 or Ed25519 public/verifying key",
            listConverter = VerificationMethodParametersConverter.class,
            validateWith = VerificationMethodKeyParametersValidator.class,
            variableArity = true)
    public Set<VerificationMethodParameters> assertionMethodKeys;

    @Parameter(names = {PARAM_NAME_LONG_AUTHENTICATION_METHOD_KEYS, PARAM_NAME_SHORT_AUTHENTICATION_METHOD_KEYS},
            description = "One or more authentication method parameter(s) - each parameter consists of a (comma-separated) key name and a PEM file containing EC P-256 or Ed25519 public/verifying key",
            listConverter = VerificationMethodParametersConverter.class,
            validateWith = VerificationMethodKeyParametersValidator.class,
            variableArity = true)
    public Set<VerificationMethodParameters> authenticationKeys;

    @Parameter(names = {PARAM_NAME_LONG_CRYPTOGRAPHIC_ALGORITHM, PARAM_NAME_SHORT_CRYPTOGRAPHIC_ALGORITHM},
            description = "Specify which king of keys to generate as assertion and authorization keys when none are provided. Available are ECP-256 and EdDSA25519")
    public CryptographicAlgorithm cryptoAlgorithm = CryptographicAlgorithm.ECP256;

    @Parameter(names = {PARAM_NAME_LONG_FORCE, PARAM_NAME_SHORT_FORCE},
            description = "Overwrite existing PEM key files, if any")
    public boolean forceOverwrite;

    /**
     * Parses the provided verification methods from {@link #assertionMethodKeys} into verification methods.
     * If none are set, this functions generates new keys and stores them in the provided directory as `assert-key-01` and
     * `assert-key-01.pub`. This function throws an exception if the files already exist and {@link #forceOverwrite} is set to false.
     *
     * @param directoryToStoreGeneratedKeys directory in which the function would store the public and private key files
     * @return all assertion methods
     * @throws IOException when the generated keys cannot be stored
     * @throws VerificationMethodException when it fails to parse the provided keys
     */
    public Set<VerificationMethod> getAssertionMethods(Path directoryToStoreGeneratedKeys) throws IOException, VerificationMethodException {
        var assertionMethods = new HashSet<VerificationMethod>();
        if (this.assertionMethodKeys != null && !this.assertionMethodKeys.isEmpty()) {
            for (VerificationMethodParameters param : this.assertionMethodKeys) {
                assertionMethods.add(VerificationMethod.of(param.key, param.jwk));
            }
        } else {
            assertionMethods.add(generateVerificationMethod(directoryToStoreGeneratedKeys, "assert-key-01"));
        }

        return assertionMethods;
    }

    /**
     * Parses the provided verification methods from {@link #authenticationKeys} into verification methods.
     * If none are set, this functions generates new keys and stores them in the provided directory as `auth-key-01` and
     * `auth-key-01.pub`. This function throws an exception if the files already exist and {@link #forceOverwrite} is set to false.
     *
     * @param directoryToStoreGeneratedKeys directory in which the function would store the public and private key files
     * @return all assertion methods
     * @throws IOException when the generated keys cannot be stored
     * @throws VerificationMethodException when it fails to parse the provided keys
     */
    public Set<VerificationMethod> getAuthentications(Path directoryToStoreGeneratedKeys) throws IOException, VerificationMethodException {
        var authentications = new HashSet<VerificationMethod>();
        if (this.authenticationKeys != null && !this.authenticationKeys.isEmpty()) {
            for (VerificationMethodParameters param : this.authenticationKeys) {
                authentications.add(VerificationMethod.of(param.key, param.jwk));
            }
        } else {
            authentications.add(generateVerificationMethod(directoryToStoreGeneratedKeys, "auth-key-01"));
        }

        return authentications;
    }

    private VerificationMethod generateVerificationMethod(Path directory, String name) throws IOException {
        FilesPrivacy.createPrivateKeyDirectoryIfDoesNotExist(directory);
        var file = new File(directory.toString(), name);

        return switch (this.cryptoAlgorithm) {
            case CryptographicAlgorithm.ECP256 ->
                    JwkUtils.generatePublicEC256VerificationMethod(name, file, this.forceOverwrite);
            case ED25519 -> JwkUtils.generatePublicEd25519VerificationMethod(name, file, this.forceOverwrite);
        };
    }
}
