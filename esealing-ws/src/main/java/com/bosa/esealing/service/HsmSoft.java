package com.bosa.esealing.service;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.util.Enumeration;
import java.util.Vector;

import jakarta.xml.bind.DatatypeConverter;

import com.bosa.esealing.exception.ESealException;
import com.bosa.esealing.model.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fall-back for the HsmPkcs11 class in case no HSM is available - only for testing.
 * Only supports EC keys, no RSA keys.
 * A PKCS12 keystore is harcoded (at the end of the file), containing 2 secp384r1 keys.
 */
class HsmSoft extends Hsm {
	private static final String POLICY = "Just for testing (software keys), pretty insecure";
	private static final String SIG_POLICY_ID = "Test signatures in software (no HSM)";

	private static final Logger LOG = LoggerFactory.getLogger(HsmSoft.class);

	protected HsmSoft() throws ESealException {
	}

	public ListResponse getCredentialsList(String userName, char[] userPwd, String certificates) throws ESealException {

		KeyStore ks = getKeyStore(userName, userPwd);

		try {
			Vector<String> credentialIds = new Vector<String>(10);
			Vector<String> certs =         new Vector<String>(10);

			Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if (ks.isKeyEntry(alias)) {
					KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)
						ks.getEntry(alias, new KeyStore.PasswordProtection(userPwd));

					credentialIds.add(alias);
					if (!"none".equals(certificates))
						certs.add(convertCerts(entry.getCertificateChain(), certificates));
				}
			}

			String[] credIdArr = new String[credentialIds.size()];
			credentialIds.toArray(credIdArr);
			String[] certArr = new String[certs.size()];
			certs.toArray(certArr);
			
			return new ListResponse("OK", null, credIdArr, certArr);
		}
		catch (Exception e) {
			LOG.error("Hsm.getCredentialsList(): " + e.toString(), e);
			throw new ESealException(500, "Internal error", e.getMessage());
		}
	}

	public InfoResponse getCredentialsInfo(String userName, char[] userPwd, String keyName, String returnCerts,
			Boolean getCertInfo, Boolean getAuthInfo) throws ESealException {
	
		KeyStore ks = getKeyStore(userName, userPwd);

		KeyStore.PrivateKeyEntry entry = getKey(ks, keyName, userPwd);

		try {
			Certificate[] chain = entry.getCertificateChain();

			return makeInfoResponse(chain, returnCerts, getCertInfo, getAuthInfo);
		}
		catch (Exception e) {
			LOG.error("Hsm.getCredentialsList(): " + e.toString(), e);
			throw new ESealException(500, "Internal error", e.getMessage());
		}
	}

	public DsvResponse signHash(String userName, char[] userPwd, String keyName, OptionalData optionalData,
			String signAlgo, Digest documentDigests) throws ESealException {

		KeyStore ks = getKeyStore(userName, userPwd);

		KeyStore.PrivateKeyEntry entry = getKey(ks, keyName, userPwd);

		try {
			String[] hashes = documentDigests.getHashes();

			PrivateKey privKey = entry.getPrivateKey();
			Certificate[] chain = entry.getCertificateChain();
			String signAlgoJava = getAndCheckSignAlgo(signAlgo, documentDigests.getHashAlgorithmOID(), privKey.getAlgorithm(), hashes[0]);
			Signature signature = Signature.getInstance(signAlgoJava);

			String[] sigs = new String[hashes.length];
			for (int i = 0; i < sigs.length; i++) {
				signature.initSign(privKey);
				signature.update(DatatypeConverter.parseBase64Binary(hashes[i]));
				sigs[i] = DatatypeConverter.printBase64Binary(signature.sign());
			}

			return makeDsvResponse(optionalData, chain, sigs, POLICY, SIG_POLICY_ID);
		}
		catch (Exception e) {
			LOG.error("Hsm.getCredentialsList(): " + e.toString(), e);
			throw new ESealException(500, "Internal error", e.getMessage());
		}
	}

	// Get the cert with the specified serialNumber
	public X509Certificate getSadSigningCert(String userName, char[] userPwd, String serialNumber) throws ESealException {
		KeyStore ks = getKeyStore(userName, userPwd);

		try {
			Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if (ks.isCertificateEntry(alias)) {
					X509Certificate ret = (X509Certificate) ks.getCertificate(alias);
					if (ret.getSerialNumber().toString(16).equals(serialNumber))
						return ret;
				}
			}
		}
		catch (Exception e) {
			LOG.error("Hsm.getSadSigningCert(): " + e.toString(), e);
			throw new ESealException(500, "Internal error", e.getMessage());
		}

		LOG.error("HSM.getSadSigningCert(): no certificate found with serialNumber = " + serialNumber);
		throw new ESealException(404, "Not found", "SAD signing certificate not found");
	}

	private KeyStore.PrivateKeyEntry getKey(KeyStore ks, String keyName, char[] pwd) throws ESealException {
		try {
			Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if (alias.equals(keyName) && ks.isKeyEntry(alias))
					return (KeyStore.PrivateKeyEntry) ks.getEntry(keyName, new KeyStore.PasswordProtection(pwd));
			}
		}
		catch (Exception e) {
			LOG.error("Hsm.getKey(): " + e.toString(), e);
			throw new ESealException(500, "Internal error", e.getMessage());
		}

		throw new ESealException(404, "Not found", "CredentialID ('" + keyName + "') not found");
	}

	private String getAndCheckSignAlgo(String signAlgoOid, String hashAlgoOid, String keyAlgo, String hashB64) throws ESealException {
		if (keyAlgo.contains("EC"))
			return "NONEwithECDSA";

		// Assume it's an RSA key
		int hashLen = hashB64.length() * 3 / 4;
		// TODO
		throw new ESealException(500, "RSA not yet supported", "try with an EC key instead...");
	}

	private KeyStore getKeyStore(String userName, char[] userPwd) throws ESealException {
		String p12Str = null;
		if ("selor".equals(userName))
			p12Str = SELOR_P12;
		else {
			LOG.info("No keystore/slot available for user '" + userName + "'");
			throw new ESealException(401, "Bad Authorization", "Bad username/password");
		}

		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			byte[] p12Bytes = DatatypeConverter.parseBase64Binary(p12Str);
			ks.load(new ByteArrayInputStream(p12Bytes), userPwd);
			
			return ks;
		}
		catch (Exception e) {
			LOG.info("Bad password specified for user '" + userName + "'");
			throw new ESealException(401, "Bad Authorization", "Bad username/password");
		}
	}

	////////////////////////////////////////////////////////

	// Contains 2 key entries (intermediate_requitment and final_recruitment) and 1 cert entry (sad), passwd = test123
	private static final String SELOR_P12 = "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";
}
