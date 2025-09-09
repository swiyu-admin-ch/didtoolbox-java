package ch.admin.bj.swiyu.didtoolbox.jcommander;

/* TODO As soon as EIDOMNI-126 is done
import ch.admin.eid.did_sidekicks.DidLogEntryJsonSchema;
import ch.admin.eid.did_sidekicks.DidLogEntryValidator;
 */

import ch.admin.eid.did_sidekicks.DidLogEntryValidatorException;
import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicReference;

public class DidLogFileParameterValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) throws ParameterException {

        final var didLogFile = new File(value);
        if (!didLogFile.isFile() || !didLogFile.exists()) {
            throw buildParameterException(name, value, null);
        }

        try {
            AtomicReference<DidLogEntryValidatorException> validatorException = new AtomicReference<>();
            var isValid = Files.lines(Paths.get(value)).anyMatch(instance -> {
                /* TODO As soon as EIDOMNI-126 is done
                try {
                    DidLogEntryValidator.Companion
                            .from(DidLogEntryJsonSchema.V03_EID_CONFORM).validate(instance);
                } catch (DidLogEntryValidatorException ex) {
                    validatorException.set(ex);
                    return false;
                }
                 */
                return true;
            });

            if (!isValid) {
                if (validatorException.get() != null) {
                    throw validatorException.get();
                }
                throw new DidLogEntryValidatorException.ValidationException("invalid DID log"); // fallback
            }

        } catch (IOException | DidLogEntryValidatorException ex) {
            throw buildParameterException(name, value, ex);
        }
    }

    private static ParameterException buildParameterException(String name, String value, Throwable cause) {
        var msg = "Parameter " + name + " should be a regular file containing a valid DID log (found " + value + ")";
        if (cause != null) {
            return new ParameterException(msg + ": " + cause.getMessage());
        }
        return new ParameterException(msg);
    }
}
