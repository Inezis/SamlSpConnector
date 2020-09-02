package sk.inezis.saml_sp_connector.exception;

public class AzureKeyVaultException extends SecurityModuleException {
    private static final long serialVersionUID = -296462606659123819L;

    public AzureKeyVaultException() {
    }

    public AzureKeyVaultException(String message) {
        super(message);
    }

    public AzureKeyVaultException(String message, Throwable cause) {
        super(message, cause);
    }

    public AzureKeyVaultException(Throwable cause) {
        super(cause);
    }

    public AzureKeyVaultException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
