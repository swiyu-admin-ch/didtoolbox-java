package ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter;

import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import com.beust.jcommander.IStringConverter;

import java.text.ParseException;

public class DidMethodParameterConverter implements IStringConverter<DidMethodEnum> {
    @Override
    public DidMethodEnum convert(String value) {
        try {
            return DidMethodEnum.parse(value);
        } catch (ParseException e) {
            // The designated validator class (if any) should already ensure the value is "convertible"
            return null;
        }
    }
}
