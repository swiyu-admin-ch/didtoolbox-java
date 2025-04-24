package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.IStringConverter;

import java.io.File;

public class DidLogFileParameterConverter implements IStringConverter<File> {
    @Override
    public File convert(String value) {
        return new File(value);
    }
}
