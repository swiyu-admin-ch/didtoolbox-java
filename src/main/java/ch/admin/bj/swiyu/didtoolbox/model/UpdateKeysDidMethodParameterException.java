package ch.admin.bj.swiyu.didtoolbox.model;

import java.io.Serial;

/**
 * The class {@link UpdateKeysDidMethodParameterException} is a <em>checked exception</em> class indicating conditions related to
 * any {@link UpdateKeysDidMethodParameter} interface implementation, that any reasonable application might want to catch.
 *
 * @see UpdateKeysDidMethodParameter
 */
public class UpdateKeysDidMethodParameterException extends Exception {

    @Serial
    private static final long serialVersionUID = -7973978845363852916L;

    public UpdateKeysDidMethodParameterException(String message) {
        super(message);
    }

    public UpdateKeysDidMethodParameterException(Exception e) {
        super(e);
    }

    public UpdateKeysDidMethodParameterException(String message, Throwable cause) {
        super(message, cause);
    }
}