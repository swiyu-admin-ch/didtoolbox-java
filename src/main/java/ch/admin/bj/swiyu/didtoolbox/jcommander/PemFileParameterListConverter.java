package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.IStringConverter;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

public class PemFileParameterListConverter implements IStringConverter<Set<File>> {
    @Override
    public Set<File> convert(String value) {
        Set<File> fileList = new HashSet<>();
        fileList.add(new File(value));
        return fileList;
    }
}
