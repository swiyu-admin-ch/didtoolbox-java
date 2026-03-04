package ch.admin.bj.swiyu.didtoolbox.model;

import java.io.Serial;

/**
 * The class {@link NextKeyHashesDidMethodParameterException} is a <em>checked exception</em> class indicating conditions related to
 * any {@link NextKeyHashesDidMethodParameter} interface implementation, that any reasonable application might want to catch.
 *
 * @see NextKeyHashesDidMethodParameter
 */
public class NextKeyHashesDidMethodParameterException extends Exception {

    @Serial
    private static final long serialVersionUID = 7178911732821562177L;

    public NextKeyHashesDidMethodParameterException(String message) {
        super(message);
    }

    public NextKeyHashesDidMethodParameterException(Exception e) {
        super(e);
    }

    public NextKeyHashesDidMethodParameterException(String message, Throwable cause) {
        super(message, cause);
    }
}