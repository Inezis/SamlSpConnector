package sk.inezis.saml_sp_connector.exception;

public class SamlValidationException extends Exception {
    private static final long serialVersionUID = -2510208894413170395L;

    public SamlValidationException() {
    }

    public SamlValidationException(String message) {
        super(message);
    }

    public SamlValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public SamlValidationException(Throwable cause) {
        super(cause);
    }

    public SamlValidationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
