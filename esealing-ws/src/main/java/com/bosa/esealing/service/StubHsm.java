package com.bosa.esealing.service;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;

import com.bosa.esealing.exception.ESealException;
import com.bosa.esealing.model.*;

import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fall-back for the HsmPkcs11 class in case no HSM is available - only for testing.
 * Only supports EC keys, no RSA keys.
 * A PKCS12 keystore is harcoded (at the end of the file), containing 2 secp384r1 keys.
 */
class StubHsm extends Hsm {
	private static final String POLICY = "Just for testing (software keys), pretty insecure";
	private static final String SIG_POLICY_ID = "Test signatures in software (no HSM)";

	private static final Logger LOG = LoggerFactory.getLogger(StubHsm.class);

	protected StubHsm() throws ESealException {
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
				signature.update(Base64.decodeBase64(hashes[i]));
				sigs[i] = Base64.encodeBase64String(signature.sign());
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
		if (!"selor".equals(userName)) {
			LOG.info("No keystore/slot available for user '" + userName + "'");
			throw new ESealException(401, "Bad Authorization", "Bad username/password");
		}

		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream("SetupHSM/stub_store.p12"), userPwd);
			return ks;
		}
		catch (Exception e) {
			e.printStackTrace();
			LOG.info("Bad password specified for user '" + userName + "'");
			throw new ESealException(401, "Bad Authorization", "Bad username/password");
		}
	}

	////////////////////////////////////////////////////////
}
