package sk.inezis.saml_sp_connector.service;

import com.microsoft.azure.keyvault.webkey.JsonWebKeyEncryptionAlgorithm;
import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;
import org.springframework.stereotype.Service;
import sk.inezis.saml_sp_connector.exception.SecurityModuleException;

import javax.crypto.SecretKey;
import java.security.cert.X509Certificate;

@Service
public interface SecurityModuleService {
    SecretKey decrypt(byte[] secretEncrypted);

    byte[] encrypt(byte[] rawData);

    byte[] sign(byte[] encryptedData, JsonWebKeySignatureAlgorithm algorithm) throws SecurityModuleException;

    byte[] unwrapKey(byte[] data, JsonWebKeyEncryptionAlgorithm algorithm);

    X509Certificate getSignCertificate() throws SecurityModuleException;
}
