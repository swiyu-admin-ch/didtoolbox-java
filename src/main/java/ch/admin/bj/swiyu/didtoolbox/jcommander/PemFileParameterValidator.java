package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.io.File;

public class PemFileParameterValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) throws ParameterException {
        File pemFile = new File(value);
        if (!pemFile.isFile() || !pemFile.exists()) {
            throw new ParameterException("Parameter " + name + " should be a regular file containing key in PEM format (found " + value + ")");
        }
    }
}
