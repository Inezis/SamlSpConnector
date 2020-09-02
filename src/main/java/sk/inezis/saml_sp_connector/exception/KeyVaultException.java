package sk.inezis.saml_sp_connector.exception;

public class KeyVaultException extends RuntimeException {
    private static final long serialVersionUID = -4761867720207849667L;

    public KeyVaultException() {
    }

    public KeyVaultException(String message) {
        super(message);
    }

    public KeyVaultException(String message, Throwable cause) {
        super(message, cause);
    }

    public KeyVaultException(Throwable cause) {
        super(cause);
    }

    public KeyVaultException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
