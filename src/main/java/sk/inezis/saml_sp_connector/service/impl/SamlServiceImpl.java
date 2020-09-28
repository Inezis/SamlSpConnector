package sk.inezis.saml_sp_connector.service.impl;

import com.onelogin.saml2.authn.AuthnRequest;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import sk.inezis.saml_sp_connector.data.AzureKeyVaultValidatedSamlResponse;
import sk.inezis.saml_sp_connector.exception.SamlValidationException;
import sk.inezis.saml_sp_connector.resolver.KeyVaultSignCertificateLazyResolver;
import sk.inezis.saml_sp_connector.service.SamlService;

import javax.annotation.PostConstruct;
import javax.xml.xpath.XPathExpressionException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

@Service
public class SamlServiceImpl implements SamlService {

    @Value("${onelogin.saml.properties.location-type}")
    private LocationType oneloginSamlPropertiesLocationType;

    @Value("${onelogin.saml.properties.path}")
    private String oneloginSamlPropertiesPath;

    @Value("${security.key-vault.key.rsa.identifier}")
    private String keyVaultKeyIdentifier;

    private final KeyVaultSignCertificateLazyResolver keyVaultSignCertificateLazyResolver;

    private Saml2Settings settings;
    
    public final static String SECURITY_DIGEST_ALGORITHM = "onelogin.saml2.security.digest_algorithm";

    public SamlServiceImpl(KeyVaultSignCertificateLazyResolver keyVaultSignCertificateLazyResolver) {
        this.keyVaultSignCertificateLazyResolver = keyVaultSignCertificateLazyResolver;
    }

    @PostConstruct
    private void initialize() throws Exception {
        Resource resource = null;
        if (oneloginSamlPropertiesLocationType == LocationType.FILE_SYSTEM) {
            resource = new FileSystemResource(oneloginSamlPropertiesPath);
        } else if (oneloginSamlPropertiesLocationType == LocationType.CLASSPATH) {
            resource = new ClassPathResource(oneloginSamlPropertiesPath);
        }

        if (resource == null) {
            throw new RuntimeException("Failed to load saml properties");
        }

        Properties properties = PropertiesLoaderUtils.loadProperties(resource);
        settings = new SettingsBuilder().fromProperties(properties).build();
        settings.setDigestAlgorithm(properties.getProperty(SECURITY_DIGEST_ALGORITHM, Constants.SHA256));
    }

    @Override
    public byte[] generateSamlRequest() throws XPathExpressionException, XMLSecurityException {
        boolean forceAuthn = true;
        boolean isPassive = false;
        boolean setNameIdPolicy = false;
        String nameIdValueReq = null;
        AuthnRequest authnRequest = new AuthnRequest(settings, forceAuthn, isPassive, setNameIdPolicy, nameIdValueReq);
        String samlRequest = authnRequest.getAuthnRequestXml();
        samlRequest = signAuthnRequest(samlRequest, settings);
        return samlRequest.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public Map<String, String> parseSamlResponse(byte[] samlResponseBase64) throws SamlValidationException {
        try {
            SamlResponse samlResponse;
            if (StringUtils.isEmpty(keyVaultKeyIdentifier)) {
                samlResponse = new SamlResponse(settings, null);
            } else {
                samlResponse = new AzureKeyVaultValidatedSamlResponse(settings, null);
            }

            samlResponse.loadXmlFromBase64(Base64.encodeBase64String(samlResponseBase64));
            samlResponse.setDestinationUrl(settings.getSpAssertionConsumerServiceUrl().toString());
            boolean isValid = samlResponse.isValid();
            if (!isValid) {
                throw new SamlValidationException("Validation of SAML response failed: " + samlResponse.getError());
            }

            HashMap<String, List<String>> samlRetVal = samlResponse.getAttributes();
            Map<String, String> retVal = new HashMap<>();
            for (Map.Entry<String, List<String>> entry : samlRetVal.entrySet()) {
                retVal.put(entry.getKey(), entry.getValue().get(0));
            }
            return retVal;
        } catch (SamlValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new SamlValidationException(e);
        }
    }

    private String signAuthnRequest(String samlRequest, Saml2Settings settings) throws XPathExpressionException, XMLSecurityException {
        Document samlRequestDoc = Util.loadXML(samlRequest);
        PrivateKey privateKey = settings.getSPkey();
        if (privateKey == null) {
            privateKey = new PrivateKeyStub();
        }

        X509Certificate sPcert = settings.getSPcert();
        if (sPcert == null) {
            sPcert = keyVaultSignCertificateLazyResolver.resolve();
        }

        return Util.addSign(samlRequestDoc, privateKey, sPcert, settings.getSignatureAlgorithm(), settings.getDigestAlgorithm());
    }

    public static class PrivateKeyStub implements PrivateKey {

        private static final long serialVersionUID = 6661620287584474446L;

        @Override
        public String getAlgorithm() {
            return null;
        }

        @Override
        public String getFormat() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public byte[] getEncoded() {
            // TODO Auto-generated method stub
            return null;
        }
    }

    enum LocationType {
        CLASSPATH,
        FILE_SYSTEM
    }
}
