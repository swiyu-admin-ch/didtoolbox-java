package ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator;

import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistory;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryException;
import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;

public class DidLogFileParameterValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) {
        final var didLogFile = new File(value);
        if (!didLogFile.isFile() || !didLogFile.exists()) {
            throw buildParameterException(name, value, new FileNotFoundException(String.format("The file '%s' doesn't exist.", didLogFile.getAbsolutePath())));
        }
        if (didLogFile.length() == 0) {
            throw buildParameterException(name, value, null);
        }

        String didLog;
        try {
            didLog = Files.readString(didLogFile.toPath());
        } catch (IOException ex) {
            throw buildParameterException(name, value, ex);
        }

        try {
            WebVerifiableHistory.resolveLog(didLog);
        } catch (WebVerifiableHistoryException ex) {
            throw buildParameterException(name, value, new IllegalArgumentException("Malformed DID log or unsupported DID method", ex));
        }
    }

    private static ParameterException buildParameterException(String name, String value, Throwable cause) {
        var msg = "Parameter " + name + " should be a regular file containing a valid DID log (found " + value + ")";
        if (cause != null) {
            var causeMsg = cause.getMessage();
            if (cause.getCause() != null) {
                causeMsg = cause.getCause().getMessage();
            }
            return new ParameterException(msg + ": " + causeMsg, cause);
        }
        return new ParameterException(msg);
    }
}
