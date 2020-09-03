package sk.inezis.saml_sp_connector.service.impl;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.KeyOperationResult;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyEncryptionAlgorithm;
import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import sk.inezis.saml_sp_connector.data.ClientKeyVaultCredentials;
import sk.inezis.saml_sp_connector.exception.AzureKeyVaultException;
import sk.inezis.saml_sp_connector.service.SecurityModuleService;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Service
public class AzureKeyVaultSecurityModuleService implements SecurityModuleService {

    @Value("${security.key-vault.application.id}")
    private String applicationId;

    @Value("${security.key-vault.application.secret}")
    private String applicationSecret;

    @Value("${security.key-vault.key.rsa.identifier}")
    private String rsaKeyIdentifier;

    @Value("${security.key-vault.cert.sign.identifier}")
    private String signCertIdentifier;

    private String signCertKeyIdentifier;

    private KeyVaultClient client;

    @PostConstruct
    public void init() throws AzureKeyVaultException {
        client = new KeyVaultClient(new ClientKeyVaultCredentials(applicationId, applicationSecret));
        signCertKeyIdentifier = getSignCertificateBundle().keyIdentifier().identifier();
    }

    @Override
    public SecretKey decrypt(byte[] encryptedData) {
        KeyOperationResult result = client.decrypt(rsaKeyIdentifier, JsonWebKeyEncryptionAlgorithm.RSA1_5, encryptedData);
        return new SecretKeySpec(result.result(), 0, result.result().length, "AES");
    }

    @Override
    public byte[] encrypt(byte[] rawData) {
        KeyOperationResult result = client.encrypt(rsaKeyIdentifier, JsonWebKeyEncryptionAlgorithm.RSA1_5, rawData);
        return result.result();
    }

    @Override
    public byte[] sign(byte[] data, JsonWebKeySignatureAlgorithm algorithm) throws AzureKeyVaultException {
        try {
            byte[] sha256EncodedData = MessageDigest.getInstance("SHA-256").digest(data);
            KeyOperationResult keyOperationResult = client.sign(signCertKeyIdentifier, algorithm, sha256EncodedData);
            return keyOperationResult.result();
        } catch (NoSuchAlgorithmException e) {
            throw new AzureKeyVaultException("HSM sign failed", e);
        }
    }
    
    @Override
	public byte[] signDigest(byte[] digestToSign, JsonWebKeySignatureAlgorithm algorithm) {
    	KeyOperationResult keyOperationResult = client.sign(signCertKeyIdentifier, algorithm, digestToSign);
    	return keyOperationResult.result();
	}

    @Override
    public byte[] unwrapKey(byte[] data, JsonWebKeyEncryptionAlgorithm algorithm) {
        KeyOperationResult keyOperationResult = client.unwrapKey(rsaKeyIdentifier, algorithm, data);
        return keyOperationResult.result();
    }

    @Override
    public X509Certificate getSignCertificate() throws AzureKeyVaultException {
        CertificateBundle certificate = getSignCertificateBundle();
        try {
            InputStream in = new ByteArrayInputStream(certificate.cer());
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (CertificateException e) {
            throw new AzureKeyVaultException("Could not create x509 sign certificate", e);
        }
    }

    private CertificateBundle getSignCertificateBundle() throws AzureKeyVaultException {
        CertificateBundle certificate = client.getCertificate(signCertIdentifier);
        if (certificate == null) {
            throw new AzureKeyVaultException("Could not get sign certificate");
        }
        return certificate;
    }
}
