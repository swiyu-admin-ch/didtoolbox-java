package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.PemFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.VerificationMethodKeyParametersValidator;
import com.beust.jcommander.Parameter;

import java.io.File;
import java.util.Set;

import static ch.admin.bj.swiyu.didtoolbox.jcommander.CommandParameterNames.*;

/**
 * The base class for all Command classes in the package that require supply of a key material.
 */
class AbstractKeyMaterialTdwCommand extends AbstractCommandBase {

    @Parameter(names = {PARAM_NAME_LONG_VERIFYING_KEY_FILES, PARAM_NAME_SHORT_VERIFYING_KEY_FILES},
            description = "One or more ed25519 public key file(s) for the DID Document’s verification method. In PEM format.",
            listConverter = PemFileParameterListConverter.class,
            //converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class,
            variableArity = true)
    public Set<File> verifyingKeyPemFiles;

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
}
