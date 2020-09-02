package sk.inezis.saml_sp_connector.data;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sk.inezis.saml_sp_connector.exception.KeyVaultException;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class ClientKeyVaultCredentials extends KeyVaultCredentials {

    private static final Logger logger = LoggerFactory.getLogger(ClientKeyVaultCredentials.class);

    private final String clientId;
    private final String clientKey;

    public ClientKeyVaultCredentials(String clientId, String clientKey) {
        this.clientId = clientId;
        this.clientKey = clientKey;
    }

    @Override
    public String doAuthenticate(String authorization, String resource, String scope) {
        AuthenticationResult token = getAccessTokenFromClientCredentials(authorization, resource, clientId, clientKey);
        return token.getAccessToken();
    }

    private AuthenticationResult getAccessTokenFromClientCredentials(String authorization, String resource, String clientId, String clientKey) {
        AuthenticationContext context;
        AuthenticationResult result;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            context = new AuthenticationContext(authorization, false, service);
            ClientCredential credentials = new ClientCredential(clientId, clientKey);
            Future<AuthenticationResult> future = context.acquireToken(resource, credentials, null);
            result = future.get();
        } catch (Exception e) {
            logger.error("Could not authenticate");
            throw new KeyVaultException(e);
        } finally {
            if (service != null) {
                service.shutdown();
            }
        }

        if (result == null) {
            throw new KeyVaultException("Authentication result was null");
        }
        return result;
    }
}
