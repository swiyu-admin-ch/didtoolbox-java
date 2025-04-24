package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.io.File;

public class DidLogFileParameterValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) throws ParameterException {
        File didLogFile = new File(value);
        if (!didLogFile.isFile() || !didLogFile.exists()) {
            throw new ParameterException("Parameter " + name + " should be a regular file containing a valid did:tdw DID log (found " + value + ")");
        }
    }
}
