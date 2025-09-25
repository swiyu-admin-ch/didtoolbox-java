package ch.admin.bj.swiyu.didtoolbox.jcommander.validator;

import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.text.ParseException;

public class DidMethodParameterValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) { // throws ParameterException {
        try {
            DidMethodEnum.parse(value);
        } catch (ParseException e) {
            throw new ParameterException(
                    "A value of the parameter " + name +
                            " should be one of the supported DID method specification versions. The supplied parameter value is invalid due to: " + e.getLocalizedMessage());
        }
    }
}
