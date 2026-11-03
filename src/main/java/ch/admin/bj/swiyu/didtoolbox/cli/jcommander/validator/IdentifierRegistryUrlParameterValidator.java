package ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class IdentifierRegistryUrlParameterValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) { // throws ParameterException {
        URL url;
        try {
            url = URL.of(new URI(value), null);
        } catch (URISyntaxException | MalformedURLException exc) {
            throw new ParameterException("Parameter " + name + " must be a regular HTTPS DID URL (found '" + value + "')", exc);
        }

        // Only https is allowed
        if (!"https".equals(url.getProtocol())) {
            throw new ParameterException("Parameter " + name + " must be a HTTPS DID URL (found '" + value + "')");
        }
    }
}
