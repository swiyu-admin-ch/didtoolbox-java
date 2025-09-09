package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.IParametersValidator;
import com.beust.jcommander.ParameterException;

import java.util.Map;

public class CommandParametersValidator implements IParametersValidator {

    @Override
    public void validate(Map<String, Object> parameters) throws ParameterException {
        validateAmbiguousParameters(parameters);
        validateBoundParameters(parameters);
        validatePrimusParameters(parameters);
    }

    private static void validateAmbiguousParameters(Map<String, Object> parameters) throws ParameterException {
        var isSigningKeyFileParamSupplied = parameters.get(CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE) != null;
        var isAnyOfJksParamsSupplied = (parameters.get(CommandParameterNames.PARAM_NAME_LONG_JKS_FILE) != null
                || parameters.get(CommandParameterNames.PARAM_NAME_SHORT_JKS_FILE) != null)
                || parameters.get(CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS) != null
                || parameters.get(CommandParameterNames.PARAM_NAME_LONG_JKS_PASSWORD) != null;
        var isAnyOfPrimusParamsSupplied = (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS) != null
                || parameters.get(CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS) != null)
                || (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS) != null
                || parameters.get(CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS) != null)
                || (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD) != null);

        if (isSigningKeyFileParamSupplied && isAnyOfJksParamsSupplied
                || isAnyOfJksParamsSupplied && isAnyOfPrimusParamsSupplied
                || isSigningKeyFileParamSupplied && isAnyOfPrimusParamsSupplied) {
            throw new ParameterException("Supplied source for the (signing/verifying) keys is ambiguous. Use one of the relevant options to supply keys");
        }
    }

    private static void validateBoundParameters(Map<String, Object> parameters) throws ParameterException {
        var isJksFileParamSupplied = (parameters.get(CommandParameterNames.PARAM_NAME_LONG_JKS_FILE) != null || parameters.get(CommandParameterNames.PARAM_NAME_SHORT_JKS_FILE) != null);
        var isJksAliasParamSupplied = parameters.get(CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS) != null;
        var isJksPasswordParamSupplied = parameters.get(CommandParameterNames.PARAM_NAME_LONG_JKS_PASSWORD) != null;

        if (isJksFileParamSupplied && !isJksAliasParamSupplied
                || !isJksFileParamSupplied && isJksAliasParamSupplied
                || !isJksAliasParamSupplied && isJksPasswordParamSupplied) {
            throw new ParameterException("Supplied JKS parameters are incomplete. Use one of the relevant options to supply missing parameters");
        }

        var isPrimusCredentialsParamSupplied = (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS) != null || parameters.get(CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS) != null);
        var isPrimusKeystoreAliasParamSupplied = (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS) != null || parameters.get(CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS) != null);
        var isPrimusKeystorePasswordParamSupplied = parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD) != null;

        if (isPrimusCredentialsParamSupplied && !isPrimusKeystoreAliasParamSupplied
                || !isPrimusCredentialsParamSupplied && isPrimusKeystoreAliasParamSupplied
                || !isPrimusKeystoreAliasParamSupplied && isPrimusKeystorePasswordParamSupplied) {
            throw new ParameterException("Supplied Primus parameters are incomplete. Use one of the relevant options to supply missing parameters");
        }
    }

    private static void validatePrimusParameters(Map<String, Object> parameters) throws ParameterException {

        if (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS) != null || parameters.get(CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS) != null) {

            if (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS) == null && parameters.get(CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS) == null) {
                throw new ParameterException("Incomplete Primus parameters supplied");
            }

        } else if (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS) != null || parameters.get(CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS) != null) {

            if (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS) != null || parameters.get(CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS) != null) {
                throw new ParameterException("Incomplete Primus parameters supplied");
            }

        } else if (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD) != null) {

            if (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS) == null || parameters.get(CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS) == null) {
                throw new ParameterException("Incomplete Primus parameters supplied");
            } else if (parameters.get(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS) == null || parameters.get(CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS) == null) {
                throw new ParameterException("Incomplete Primus parameters supplied");
            }
        }
    }
}