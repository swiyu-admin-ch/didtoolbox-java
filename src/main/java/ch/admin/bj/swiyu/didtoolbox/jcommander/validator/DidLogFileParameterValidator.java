package ch.admin.bj.swiyu.didtoolbox.jcommander.validator;

import ch.admin.bj.swiyu.didtoolbox.model.*;
import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class DidLogFileParameterValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) {

        final var didLogFile = new File(value);
        if (!didLogFile.isFile() || !didLogFile.exists() || didLogFile.length() == 0) {
            throw buildParameterException(name, value, null);
        }

        String didLog;
        try {
            didLog = Files.readString(didLogFile.toPath());
        } catch (IOException ex) {
            throw buildParameterException(name, value, ex);
        }

        try {
            TdwDidLogMetaPeeker.peek(didLog); // assume a did:tdw log
        } catch (MalformedTdwDidLogMetaPeekerException ignore) { // not a did:tdw log at all
            try {
                WebVerifiableHistoryDidLogMetaPeeker.peek(didLog); // assume a did:webvh log
            } catch (MalformedWebVerifiableHistoryDidLogMetaPeekerException exc) { // not a did:webvh log at all
                // none of the (known) kind
                throw buildParameterException(name, value, new IllegalArgumentException("Malformed DID log or unsupported DID method", exc)); //NOPMD PreserveStackTrace: is not relevant
            } catch (DidLogMetaPeekerException exc) { // not a valid did:webvh log
                throw buildParameterException(name, value, exc); //NOPMD PreserveStackTrace: is not relevant
            }
        } catch (DidLogMetaPeekerException ex) { // not a valid did:tdw log
            throw buildParameterException(name, value, ex);
        }
    }

    private static ParameterException buildParameterException(String name, String value, Throwable cause) {
        var msg = "Parameter " + name + " should be a regular file containing a valid DID log (found " + value + ")";
        if (cause != null) {
            var causeMsg = cause.getMessage();
            if (cause.getCause() != null) {
                causeMsg = cause.getCause().getMessage();
            }
            return new ParameterException(msg + ": " + causeMsg);
        }
        return new ParameterException(msg);
    }
}
