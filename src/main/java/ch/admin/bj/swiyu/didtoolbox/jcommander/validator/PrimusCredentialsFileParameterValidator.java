package ch.admin.bj.swiyu.didtoolbox.jcommander.validator;

import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreInitializationException;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreLoader;
import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class PrimusCredentialsFileParameterValidator implements IParameterValidator {
    @SuppressWarnings("PMD.EmptyCatchBlock")
    @Override
    public void validate(String name, String value) { // throws ParameterException {
        var file = new File(value);
        if (!file.isFile() || !file.exists()) {
            throw new ParameterException("Parameter " + name + " should be a regular properties file featuring Securosys Primus credentials (found " + value + ")");
        }

        try {
            new PrimusKeyStoreLoader(file);
        } catch (PrimusKeyStoreInitializationException exc) {
            throw new ParameterException("Parameter value '" + value + "' do may feature all valid Securosys Primus credentials. "
                    + "However, Securosys Primus Key Store could not be initialized regardless of it due to: " + exc.getMessage());
        } catch (CertificateException | IOException | NoSuchAlgorithmException ignore) {
        }
    }
}
