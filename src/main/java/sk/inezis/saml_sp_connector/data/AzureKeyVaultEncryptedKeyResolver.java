package sk.inezis.saml_sp_connector.data;

import com.microsoft.azure.keyvault.webkey.JsonWebKeyEncryptionAlgorithm;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLCipherInput;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.keyresolver.implementations.EncryptedKeyResolver;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.w3c.dom.Element;
import sk.inezis.saml_sp_connector.service.SecurityModuleService;
import sk.inezis.saml_sp_connector.util.AutowireHelper;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class AzureKeyVaultEncryptedKeyResolver extends EncryptedKeyResolver {
    private final Logger LOG = LoggerFactory.getLogger(AzureKeyVaultEncryptedKeyResolver.class);

    private final String myAlgorithm;
    private Key myKek;

    @Autowired
    private SecurityModuleService securityModuleService;

    public AzureKeyVaultEncryptedKeyResolver(String algorithm) {
        super(algorithm);
        myAlgorithm = algorithm;
        AutowireHelper.autowire(this, this.securityModuleService);
    }

    public AzureKeyVaultEncryptedKeyResolver(String algorithm, Key kek) {
        super(algorithm, kek);
        myAlgorithm = algorithm;
        myKek = kek;
        AutowireHelper.autowire(this, this.securityModuleService);
    }

    @Override
    public SecretKey engineLookupAndResolveSecretKey(Element element, String baseURI, StorageResolver storage) {
        if (element == null) {
            return null;
        }

        LOG.debug("EncryptedKeyResolver - Can I resolve {}", element.getTagName());

        SecretKey key = null;
        boolean isEncryptedKey =
                XMLUtils.elementIsInEncryptionSpace(element, EncryptionConstants._TAG_ENCRYPTEDKEY);
        if (isEncryptedKey) {
            LOG.debug("Passed an Encrypted Key");
            try {
                XMLCipher cipher = XMLCipher.getInstance();
                cipher.init(XMLCipher.UNWRAP_MODE, myKek);
                EncryptedKey ek = cipher.loadEncryptedKey(element);

                // Obtain the encrypted octets
                XMLCipherInput cipherInput = new XMLCipherInput(ek);
                cipherInput.setSecureValidation(secureValidation);
                byte[] encryptedBytes = cipherInput.getBytes();
                String jceKeyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(myAlgorithm);

                byte[] unwrappedKey =
                        securityModuleService.unwrapKey(encryptedBytes, JsonWebKeyEncryptionAlgorithm.RSA_OAEP);
                key = new SecretKeySpec(unwrappedKey, jceKeyAlgorithm);
            } catch (XMLEncryptionException e) {
                LOG.debug(e.getMessage(), e);
            }
        }

        return key;
    }
}
