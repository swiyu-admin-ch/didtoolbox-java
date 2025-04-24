package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.IParametersValidator;
import com.beust.jcommander.ParameterException;

import java.util.Map;

public class TdwCommandParametersValidator implements IParametersValidator {

    @Override
    public void validate(Map<String, Object> parameters) throws ParameterException {

        /* TODO "ambiguous signing key source supplied"
        if (signingKeyPemFile != null && verifyingKeyPemFiles != null &&
                jksFile != null && jksPassword != null && jksAlias != null &&
                primus != null && primusKeyAlias != null) {
            overAndOut(jc, parsedCommandName, "Supplied source for the (signing/verifying) keys is ambiguous. Use one of the relevant options to supply keys");
        }
         */

        validatePrimusParameters(parameters);
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