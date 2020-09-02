package sk.inezis.saml_sp_connector.service;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.springframework.stereotype.Service;
import sk.inezis.saml_sp_connector.exception.SamlValidationException;

import javax.xml.xpath.XPathExpressionException;
import java.util.Map;

@Service
public interface SamlService {
    byte[] generateSamlRequest() throws XPathExpressionException, XMLSecurityException;

    Map<String, String> parseSamlResponse(byte[] samlResponseBase64) throws SamlValidationException;
}
