package ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter;

import com.beust.jcommander.IStringConverter;

import java.io.File;

public class JksFileParameterConverter implements IStringConverter<File> {
    @Override
    public File convert(String value) {
        return new File(value);
    }
}
