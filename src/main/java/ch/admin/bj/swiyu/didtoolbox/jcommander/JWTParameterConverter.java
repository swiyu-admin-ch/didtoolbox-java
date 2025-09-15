package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.IStringConverter;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;

public class JWTParameterConverter implements IStringConverter<SignedJWT> {
    @Override
    public SignedJWT convert(String value) {
        try {
            return SignedJWT.parse(value);
        } catch (ParseException e) {
            // The validator class (if any) should already ensure the value is "convertible"
            return null;
        }
    }
}
