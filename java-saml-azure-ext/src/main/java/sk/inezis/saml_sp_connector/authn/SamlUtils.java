package sk.inezis.saml_sp_connector.authn;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.xpath.XPathExpressionException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.w3c.dom.Document;

import com.onelogin.saml2.authn.AuthnRequest;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Util;

public class SamlUtils {
	
	private static Saml2Settings settings;
	
	private static synchronized void initialize() throws Error {
		if(settings == null) {
			settings = new SettingsBuilder().fromFile("onelogin.saml.properties").build();
		}
	}

	public static String generateSamlRequest() throws Error, XPathExpressionException, XMLSecurityException {
		initialize();
		boolean forceAuthn = true;
		boolean isPassive = false;
		boolean setNameIdPolicy = false;
		String nameIdValueReq = null; 
		AuthnRequest authnRequest = new AuthnRequest(settings, forceAuthn, isPassive, setNameIdPolicy, nameIdValueReq);
		String samlRequest = authnRequest.getAuthnRequestXml();
		samlRequest = signAuthnRequest(samlRequest, settings);
		return Util.base64encoder(samlRequest);
	}
	
	public static Map<String, String> parseSamlResponse(String samlResponseBase64) throws Exception {
		initialize();
		SamlResponse samlResponse = new SamlResponse(settings, null);
		samlResponse.loadXmlFromBase64(samlResponseBase64);
		samlResponse.setDestinationUrl(settings.getSpAssertionConsumerServiceUrl().toString());
		boolean isValid = samlResponse.isValid();
			if(!isValid) {
				throw new Exception("Validation of SAML response failed: " + samlResponse.getError());
		}
		HashMap<String, List<String>> samlRetVal = samlResponse.getAttributes();
		Map<String, String> retVal = new HashMap<String, String>();
		Iterator<Map.Entry<String, List<String>>> itr = samlRetVal.entrySet().iterator();
		while(itr.hasNext()) {
			Map.Entry<String, List<String>> entry = itr.next(); 
			retVal.put(entry.getKey(), entry.getValue().get(0));
		}
		return retVal;
	}
	
	private static String signAuthnRequest(String samlRequest, Saml2Settings settings) throws XPathExpressionException, XMLSecurityException {
		Document samlRequestDoc = Util.loadXML(samlRequest);
        String signedSamlRequest = Util.addSign(samlRequestDoc, settings.getSPkey(), settings.getSPcert(), settings.getSignatureAlgorithm(), settings.getDigestAlgorithm());
        return signedSamlRequest;
	}
	
}
