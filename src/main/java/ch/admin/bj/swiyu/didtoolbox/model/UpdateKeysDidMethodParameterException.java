package ch.admin.bj.swiyu.didtoolbox.model;

/**
 * The class {@link UpdateKeysDidMethodParameterException} is a <em>checked exception</em> class indicating conditions related to
 * any {@link UpdateKeysDidMethodParameter} interface implementation, that any reasonable application might want to catch.
 *
 * @see UpdateKeysDidMethodParameter
 */
public class UpdateKeysDidMethodParameterException extends Exception {
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