package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.IParametersValidator;
import com.beust.jcommander.ParameterException;

import java.util.Map;

import static ch.admin.bj.swiyu.didtoolbox.CreateTdwCommand.*;

public class CreateTdwCommandParametersValidator implements IParametersValidator {

    @Override
    public void validate(Map<String, Object> parameters) throws ParameterException {

        /* TODO "ambiguous signing key source supplied"
        if (signingKeyPemFile != null && verifyingKeyPemFiles != null &&
                jksFile != null && jksPassword != null && jksAlias != null &&
                primus != null && primusKeyAlias != null && primusKeyPassword != null) {
            overAndOut(jc, parsedCommandName, "Supplied source for the (signing/verifying) keys is ambiguous. Use one of the relevant options to supply keys");
        }
         */

        validatePrimusParameters(parameters);
    }

    private static void validatePrimusParameters(Map<String, Object> parameters) throws ParameterException {

        if (parameters.get(PARAM_NAME_LONG_PRIMUS_KEYSTORE) != null || parameters.get(PARAM_NAME_SHORT_PRIMUS_KEYSTORE) != null) {

            if (parameters.get(PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS) == null && parameters.get(PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS) == null) {
                throw new ParameterException("Incomplete Primus parameters supplied");
            /*
            } else if (parameters.get(PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD) == null && parameters.get(PARAM_NAME_SHORT_PRIMUS_KEYSTORE_PASSWORD) == null) {
                throw new ParameterException("Incomplete Primus parameters supplied");
            */
            }

        } else if (parameters.get(PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS) != null || parameters.get(PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS) != null) {

            if (parameters.get(PARAM_NAME_LONG_PRIMUS_KEYSTORE) != null || parameters.get(PARAM_NAME_SHORT_PRIMUS_KEYSTORE) != null) {
                throw new ParameterException("Incomplete Primus parameters supplied");
            /*
            } else if (parameters.get(PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD) == null || parameters.get(PARAM_NAME_SHORT_PRIMUS_KEYSTORE_PASSWORD) == null) {
                throw new ParameterException("Incomplete Primus parameters supplied");
            */
            }

        } else if (parameters.get(PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD) != null || parameters.get(PARAM_NAME_SHORT_PRIMUS_KEYSTORE_PASSWORD) != null) {

            if (parameters.get(PARAM_NAME_LONG_PRIMUS_KEYSTORE) == null || parameters.get(PARAM_NAME_SHORT_PRIMUS_KEYSTORE) == null) {
                throw new ParameterException("Incomplete Primus parameters supplied");
            } else if (parameters.get(PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS) == null || parameters.get(PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS) == null) {
                throw new ParameterException("Incomplete Primus parameters supplied");
            }
        }
    }
}