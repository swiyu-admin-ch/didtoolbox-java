package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.IStringConverter;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class IdentifierRegistryUrlParameterConverter implements IStringConverter<URL> {
    @Override
    public URL convert(String value) {
        try {
            return URL.of(new URI(value), null);
        } catch (URISyntaxException | MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
}
