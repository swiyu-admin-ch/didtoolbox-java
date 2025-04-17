package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreInitializationException;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreLoader;
import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;

import java.io.File;

public class PrimusCredentialsFileParameterConverter implements IStringConverter<PrimusKeyStoreLoader> {
    @Override
    public PrimusKeyStoreLoader convert(String value) {

        try {
            return new PrimusKeyStoreLoader(new File(value));
        } catch (PrimusKeyStoreInitializationException exc) {
            throw new ParameterException("Parameter value '" + value + "' do may feature all valid Securosys Primus credentials. "
                    + "However, Securosys Primus Key Store could not be initialized regardless of it. "
                    + "Please, ensure the required lib/primusX-java[8|11].jar libraries exist on the system");
        } catch (Exception ignore) {
        }

        try {
            return new PrimusKeyStoreLoader();
        } catch (Exception exc) {
            throw new ParameterException("Securosys Primus Key Store could not be initialized regardless of it. "
                    + "Please, ensure the required lib/primusX-java[8|11].jar libraries exist on the system");
        }
    }
}
