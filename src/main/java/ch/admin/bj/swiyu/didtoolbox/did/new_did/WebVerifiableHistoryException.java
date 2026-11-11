package ch.admin.bj.swiyu.didtoolbox.did.new_did;

public class WebVerifiableHistoryException extends Exception {

    public WebVerifiableHistoryException(String message) {
        super(message);
    }

    public WebVerifiableHistoryException(Exception e) {
        super(e);
    }

    public WebVerifiableHistoryException(String message, Throwable cause) {
        super(message, cause);
    }

}
