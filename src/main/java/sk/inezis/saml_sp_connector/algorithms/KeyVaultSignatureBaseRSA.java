package sk.inezis.saml_sp_connector.algorithms;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.xml.security.algorithms.implementations.SignatureBaseRSA;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.springframework.beans.factory.annotation.Autowired;

import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;

import sk.inezis.saml_sp_connector.service.SecurityModuleService;
import sk.inezis.saml_sp_connector.util.AutowireHelper;

public abstract class KeyVaultSignatureBaseRSA extends SignatureBaseRSA {
	
	protected final MessageDigest md;
	private boolean digestReset;
	
	protected static final int UNINITIALIZED = 0;
    protected static final int SIGN = 2;
    protected static final int VERIFY = 3;
	protected int state = UNINITIALIZED;
	
	@Autowired SecurityModuleService securityModuleService;

	public KeyVaultSignatureBaseRSA() throws XMLSignatureException {
		super();
		AutowireHelper.getInstance().autowire(this, this.securityModuleService);
		String algorithmID = getDigestAlgorithm();
		try {
            md = MessageDigest.getInstance(algorithmID);
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSignatureException(e);
        }
	}
	
	protected String getDigestAlgorithm() throws XMLSignatureException {
		String algorithm = this.engineGetURI();
		if(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256.equals(algorithm)) {
			return "SHA-256";
		}
		if(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384.equals(algorithm)) {
			return "SHA-384";
		}
		if(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512.equals(algorithm)) {
			return "SHA-512";
		}
		throw new XMLSignatureException("Unsupported signature algorithm");
	}
	
	protected JsonWebKeySignatureAlgorithm getJsonWebKeySignatureAlgorithm() throws XMLSignatureException {
		String algorithm = this.engineGetURI();
		if(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256.equals(algorithm)) {
			return JsonWebKeySignatureAlgorithm.RS256;
		}
		if(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384.equals(algorithm)) {
			return JsonWebKeySignatureAlgorithm.RS384;
		}
		if(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512.equals(algorithm)) {
			return JsonWebKeySignatureAlgorithm.RS512;
		}
		throw new XMLSignatureException("Unsupported signature algorithm");
	}
	
	protected void resetDigest() {
        if (digestReset == false) {
            md.reset();
            digestReset = true;
        }
    }

	protected byte[] getDigestValue() {
        digestReset = true;
        return md.digest();
    }
	
	@Override
	protected void engineInitSign(Key privateKey, SecureRandom secureRandom) throws XMLSignatureException {
		state = SIGN;
		resetDigest();
	}

	@Override
	protected void engineInitVerify(Key publicKey) throws XMLSignatureException {
		super.engineInitVerify(publicKey);
		state = VERIFY;
		resetDigest();
	}

	@Override
	protected byte[] engineSign() throws XMLSignatureException {
		try {
			byte[] digest = getDigestValue();
			try {
				return securityModuleService.signDigest(digest, getJsonWebKeySignatureAlgorithm());
			} catch (Exception e) {
				throw new XMLSignatureException(e);
			}
		} finally {
			resetDigest();
		}
	}
	
	@Override
	protected boolean engineVerify(byte[] signature) throws XMLSignatureException {
		resetDigest();
		return super.engineVerify(signature);
	}

	@Override
	protected void engineUpdate(byte[] input) throws XMLSignatureException {
		md.update(input);
        digestReset = false;
        if(state == VERIFY) {
        	super.engineUpdate(input);
        }
	}

	@Override
	protected void engineUpdate(byte input) throws XMLSignatureException {
		md.update(input);
        digestReset = false;
        if(state == VERIFY) {
        	super.engineUpdate(input);
        }
	}

	@Override
	protected void engineUpdate(byte[] buf, int offset, int len) throws XMLSignatureException {
		 md.update(buf, offset, len);
	     digestReset = false;
	     if(state == VERIFY) {
	    	 super.engineUpdate(buf, offset, len);
	     }
	}

	public static class KeyVaultSignatureRSASHA256 extends KeyVaultSignatureBaseRSA {

        public KeyVaultSignatureRSASHA256() throws XMLSignatureException {
            super();
        }

        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
        }
    }
	
	public static class KeyVaultSignatureRSASHA384 extends KeyVaultSignatureBaseRSA {

        public KeyVaultSignatureRSASHA384() throws XMLSignatureException {
            super();
        }

        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384;
        }
    }
	
	public static class KeyVaultSignatureRSASHA512 extends KeyVaultSignatureBaseRSA {

        public KeyVaultSignatureRSASHA512() throws XMLSignatureException {
            super();
        }

        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512;
        }
    }
}
