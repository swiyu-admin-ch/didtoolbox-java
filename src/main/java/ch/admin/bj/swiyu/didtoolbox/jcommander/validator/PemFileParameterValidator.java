package ch.admin.bj.swiyu.didtoolbox.jcommander.validator;

import ch.admin.bj.swiyu.didtoolbox.PemUtils;
import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.io.File;
import java.io.IOException;

public class PemFileParameterValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) { // throws ParameterException {
        var file = new File(value);
        if (!file.isFile() || !file.exists()) {
            throw new ParameterException("Parameter " + name + " should be a regular file containing key in PEM format (found " + value + ")");
        }

        try {
            PemUtils.parsePEMFile(file);
        } catch (IOException e) {
            throw new ParameterException("Parameter " + name + " should be a regular file containing key in PEM format (found " + value + ")");
        }
    }
}
