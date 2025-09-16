package ch.admin.bj.swiyu.didtoolbox.jcommander.validator;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;

public class JWTParameterValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) throws ParameterException {
        try {
            SignedJWT.parse(value);
        } catch (ParseException e) {
            throw new ParameterException("Parameter " + name + " should be a valid JWT. Failed to parse parameter: " + e.getLocalizedMessage());
        }
    }
}
