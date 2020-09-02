package sk.inezis.saml_sp_connector.exception;

public class SecurityModuleException extends Exception {
    private static final long serialVersionUID = 1317609590049437480L;

    public SecurityModuleException() {
    }

    public SecurityModuleException(String message) {
        super(message);
    }

    public SecurityModuleException(String message, Throwable cause) {
        super(message, cause);
    }

    public SecurityModuleException(Throwable cause) {
        super(cause);
    }

    public SecurityModuleException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
