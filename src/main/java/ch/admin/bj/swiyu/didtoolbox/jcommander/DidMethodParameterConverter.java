package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
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
