package sk.inezis.saml_sp_connector.resolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import sk.inezis.saml_sp_connector.exception.SecurityModuleException;
import sk.inezis.saml_sp_connector.service.SecurityModuleService;

import java.security.cert.X509Certificate;

@Component
public class KeyVaultSignCertificateLazyResolver {
    private static final Logger logger = LoggerFactory.getLogger(KeyVaultSignCertificateLazyResolver.class);

    private X509Certificate x509Certificate;

    private final SecurityModuleService securityModuleService;

    public KeyVaultSignCertificateLazyResolver(SecurityModuleService securityModuleService) {
        this.securityModuleService = securityModuleService;
    }

    public synchronized X509Certificate resolve() {
        if (x509Certificate == null) {
            try {
                x509Certificate = securityModuleService.getSignCertificate();
            } catch (SecurityModuleException e) {
                logger.error(e.getMessage(), e);
            }
        }

        return x509Certificate;
    }
}
