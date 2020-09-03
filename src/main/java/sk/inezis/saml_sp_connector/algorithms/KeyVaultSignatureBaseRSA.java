package sk.inezis.saml_sp_connector.algorithms;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;

import org.apache.xml.security.algorithms.implementations.SignatureBaseRSA;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.springframework.beans.factory.annotation.Autowired;

import sk.inezis.saml_sp_connector.service.SecurityModuleService;
import sk.inezis.saml_sp_connector.util.AutowireHelper;

public abstract class KeyVaultSignatureBaseRSA extends SignatureBaseRSA {
	
	protected final MessageDigest md;
	private boolean digestReset;
	
	@Autowired SecurityModuleService securityModuleService;

	public KeyVaultSignatureBaseRSA() throws XMLSignatureException {
		super();
		AutowireHelper.getInstance().autowire(this, this.securityModuleService);
		String algorithmID = getDigestAlgorithm();
		try {
            md = MessageDigest.getInstance(algorithmID);
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
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
		throw new XMLSignatureException("Cannot convert digest algorithm");
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
		super.engineInitSign(privateKey, secureRandom);
		resetDigest();
	}

	@Override
	protected void engineInitVerify(Key publicKey) throws XMLSignatureException {
		super.engineInitVerify(publicKey);
		resetDigest();
	}

	@Override
	protected byte[] engineSign() throws XMLSignatureException {
		try {
			
		} finally {
			resetDigest();
		}
		return super.engineSign();
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
		super.engineUpdate(input);
	}

	@Override
	protected void engineUpdate(byte input) throws XMLSignatureException {
		md.update(input);
        digestReset = false;
		super.engineUpdate(input);
	}

	@Override
	protected void engineUpdate(byte[] buf, int offset, int len) throws XMLSignatureException {
		 md.update(buf, offset, len);
	     digestReset = false;
		super.engineUpdate(buf, offset, len);
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
