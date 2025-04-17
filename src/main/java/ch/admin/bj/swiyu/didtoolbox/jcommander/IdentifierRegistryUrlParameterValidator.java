package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class IdentifierRegistryUrlParameterValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) throws ParameterException {
        URL url;
        var exc = new ParameterException("Parameter " + name + " should be a regular HTTP(S) DID URL (found '" + value + "')");
        try {
            url = URL.of(new URI(value), null);
        } catch (URISyntaxException | MalformedURLException e) {
            throw exc;
        }

        if (!url.getProtocol().startsWith("http")) {
            throw exc;
        }
    }
}
