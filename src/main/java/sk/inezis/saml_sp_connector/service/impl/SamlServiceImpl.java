package sk.inezis.saml_sp_connector.service.impl;

import com.onelogin.saml2.authn.AuthnRequest;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Util;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import sk.inezis.saml_sp_connector.exception.SamlValidationException;
import sk.inezis.saml_sp_connector.service.SamlService;

import javax.annotation.PostConstruct;
import javax.xml.xpath.XPathExpressionException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class SamlServiceImpl implements SamlService {

    @Value("${onelogin.saml.properties.path}")
    private String oneloginSamlPropertiesPath;

    private Saml2Settings settings;

    @PostConstruct
    private void initialize() throws Error {
        settings = new SettingsBuilder().fromFile(oneloginSamlPropertiesPath).build();
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
        return Util.base64encoder(samlRequest).getBytes();
    }

    @Override
    public Map<String, String> parseSamlResponse(byte[] samlResponseBase64) throws SamlValidationException {
        try {
            SamlResponse samlResponse = new SamlResponse(settings, null);
            samlResponse.loadXmlFromBase64(new String(samlResponseBase64, StandardCharsets.UTF_8));
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
        String signedSamlRequest = Util.addSign(samlRequestDoc, settings.getSPkey(), settings.getSPcert(), settings.getSignatureAlgorithm(), settings.getDigestAlgorithm());
        return signedSamlRequest;
    }
}
