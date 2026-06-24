package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.PemFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.VerificationMethodKeyParametersValidator;
import com.beust.jcommander.Parameter;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.MLDSAKeyFactorySpi;

import java.io.File;
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
            description = "One or more ed25519 public key file(s) for the DID Document’s verification method. In PEM format.",
            listConverter = PemFileParameterListConverter.class,
            validateWith = PemFileParameterValidator.class,
            variableArity = true)
    public Set<File> verifyingKeyPemFiles = new HashSet<>();

    @Parameter(names = {PARAM_NAME_LONG_NEXT_VERIFYING_KEY_FILES, PARAM_NAME_SHORT_NEXT_VERIFYING_KEY_FILES},
            description = "One or more ed25519 public key file(s) to be used as 'pre-rotation' keys. In PEM format. Using the CLI option activates 'key pre-rotation'. Analogously, deactivating 'key pre-rotation' goes simply by omitting this option altogether",
            listConverter = PemFileParameterListConverter.class,
            validateWith = PemFileParameterValidator.class,
            variableArity = true)
    public Set<File> nextVerifyingKeyPemFiles = new HashSet<>();

    // TODO@MP improve documentation
    @Parameter(names = {PARAM_NAME_LONG_GENERATE_NEXT_VERIFYING_KEY, PARAM_NAME_SHORT_GENERATE_NEXT_VERIFYING_KEY},
            description = "Generates a new ed25519 key pair to be used as the next signing key. The generated key pair is stored in the `.didtoolbox`. CAUTION: using `-f` can override existing keys in the directory, make sure to back them up. Cannot be used together with the generate verifying key next flag ('-gv')")
    public boolean shouldGenerateNextVerifyingKeyPem;

    @Parameter(names = {PARAM_NAME_LONG_ASSERTION_METHOD_KEYS, PARAM_NAME_SHORT_ASSERTION_METHOD_KEYS},
            description = "One or more assertion method parameter(s) - each parameter consists of a (comma-separated) key name and a PEM file containing EC P-256 public/verifying key",
            listConverter = VerificationMethodParametersConverter.class,
            validateWith = VerificationMethodKeyParametersValidator.class,
            variableArity = true)
    public Set<VerificationMethodParameters> assertionMethodKeys;

    @Parameter(names = {PARAM_NAME_LONG_AUTHENTICATION_METHOD_KEYS, PARAM_NAME_SHORT_AUTHENTICATION_METHOD_KEYS},
            description = "One or more authentication method parameter(s) - each parameter consists of a (comma-separated) key name and a PEM file containing EC P-256 public/verifying key",
            listConverter = VerificationMethodParametersConverter.class,
            validateWith = VerificationMethodKeyParametersValidator.class,
            variableArity = true)
    public Set<VerificationMethodParameters> authenticationKeys;

    @Parameter(names = {"--force-overwrite", "-f"},
            description = "Overwrite existing PEM key files, if any")
    public boolean forceOverwrite;
}
