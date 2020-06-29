package com.zetes.projects.bosa.esealing.service;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAPublicKey;
import java.io.ByteArrayInputStream;
import java.util.Enumeration;
import java.util.Vector;
import java.text.SimpleDateFormat;
import javax.xml.bind.DatatypeConverter;

import com.zetes.projects.bosa.esealing.exception.ESealException;
import com.zetes.projects.bosa.esealing.model.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Access to the HSM.
 * <pre>
 * Mapping:
 *   username                   = HSM slot userName
 *   userPwd + internal secret  = HSM slot passwd
 *   credentialID               = HSM key label
 * </pre>
 */
class Hsm {

	private static final String POLICY = "Just for testing, pretty insecure";
	private static final String SIG_POLICY_ID = "Test signatures in software (no HSM)";
	private static final String SCAL = "SCAL1";

	private static final Logger LOG = LoggerFactory.getLogger(Hsm.class);

	private static final SimpleDateFormat sdf = new SimpleDateFormat("YYYYMMDDHHMMSSZ");

	private static Hsm hsm;

	public static Hsm getHsm() throws ESealException {
		if (null == hsm)
			hsm = new Hsm();
		return hsm;
	}

	////////////////////////////////////////////////////////

	private Hsm() throws ESealException {
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

			boolean needCertAndKeyInfo = Boolean.TRUE.equals(getCertInfo);

			Cert cert = needCertAndKeyInfo ? makeCertInfo(chain, returnCerts) : null;

			Key key = needCertAndKeyInfo ? makeKeyInfo(chain[0]) : null;

			Boolean multisign = Boolean.TRUE;

			String authMode = Boolean.TRUE.equals(getAuthInfo) ? SADChecker.getInstance().getAuthMode() : null;

			return new InfoResponse(cert, key, multisign, "OK", null, authMode, SCAL);
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

			return makeDsvResponse(optionalData, chain, sigs);
		}
		catch (Exception e) {
			LOG.error("Hsm.getCredentialsList(): " + e.toString(), e);
			throw new ESealException(500, "Internal error", e.getMessage());
		}
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
			return "NoneWithECDSA";

		// Assume it's an RSA key
		int hashLen = hashB64.length() * 3 / 4;
		// TODO
		throw new ESealException(500, "RSA not yet supported", "try with an EC key instead...");
	}

	private DsvResponse makeDsvResponse(OptionalData optData, Certificate[] chain, String[] sigs) throws Exception {
		boolean needCertAndKeyInfo = null != optData && Boolean.TRUE.equals(optData.getReturnSigningCertificateInfo());
		Cert cert = needCertAndKeyInfo ? makeCertInfo(chain, "chain") : null;
		Key key = needCertAndKeyInfo ?   makeKeyInfo(chain[0]) : null;

		Boolean multisign = (null != optData && Boolean.TRUE.equals(optData.getReturnSupportMultiSignatureInfo())) ? Boolean.TRUE : false;

		String policy = (null != optData && Boolean.TRUE.equals(optData.getReturnServicePolicyInfo())) ? POLICY : null;

		String responseID = (new Long(System.nanoTime())).toString(36);

		String signaturePolicyID = (null != optData && Boolean.TRUE.equals(optData.getReturnSignatureCreationPolicyInfo())) ? SIG_POLICY_ID : null;
		String[] signaturePolicyLocations =  null;

		return new DsvResponse(cert, key, multisign, "OK", null, policy, responseID, signaturePolicyID, signaturePolicyLocations, sigs);
	}

	private Cert makeCertInfo(Certificate[] chain, String returnCerts) throws Exception {
		X509Certificate signingCert = (X509Certificate) chain[0];

		String status = System.currentTimeMillis() < signingCert.getNotAfter().getTime() ? "valid" : "expired";

		String[] certificates = null;
		if (!"none".equals(returnCerts)) {
			certificates = new String[chain.length];
			int len = "chain".equals(returnCerts) ? chain.length : 1;
			for (int i = 0; i < len; i++)
				certificates[i] = DatatypeConverter.printBase64Binary(chain[i].getEncoded());
		}

		String validFrom = sdf.format(signingCert.getNotBefore());

		String validTo = sdf.format(signingCert.getNotAfter());

		String issuerDN = signingCert.getIssuerX500Principal().toString();

		String serialNumber = signingCert.getSerialNumber().toString(16);

		String subjectDN = signingCert.getSubjectX500Principal().toString();
		
		return new Cert(status, certificates, validFrom, validTo, issuerDN, serialNumber, subjectDN);
	}

	private Key makeKeyInfo(Certificate signingCert) throws Exception {
		PublicKey pubKey = signingCert.getPublicKey();
		
		int keyLen = 0;
		String curve = null;
		if (pubKey instanceof ECKey) {
			keyLen = ((ECKey) pubKey).getParams().getCurve().getField().getFieldSize();
			// getEncoded() result looks like this:
			//   0 118: SEQUENCE {
			//     2  16:   SEQUENCE {
			//     4   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
			//    13   5:     OBJECT IDENTIFIER secp384r1 (1 3 132 0 34)
			//          :     }
			//    20  98:   BIT STRING
			//          :     04 22 13 13 F5 E9 50 DB 81 BC 3A EC 06 06 27 3A
			//                ...
			Der der = new Der(pubKey.getEncoded());
			der = der.getChild(0x30);
			der = der.getChild(0x06, 1); // this is the 2nd object identifier
			curve = der.getOidValue();
		}
		else if (pubKey instanceof RSAPublicKey)
			keyLen = ((RSAPublicKey) pubKey).getModulus().bitLength();

		String status = "enabled";

		String[] algo = new String[] {
			"1.2.840.10045.4.1",       // ecdsa-with-SHA1
			"1.2.840.10045.4.2",       // ecdsa-with-Recommended
			"1.2.840.10045.4.3.1",     // ecdsa-with-SHA224
			"1.2.840.10045.4.3.2",     // ecdsa-with-SHA256
			"1.2.840.10045.4.3.3",     // ecdsa-with-SHA384
			"1.2.840.10045.4.3.4",     // ecdsa-with-SHA512
		};

		Integer len = new Integer(keyLen);

		return new Key(status, algo, len, curve);
	}

	private String convertCerts(Certificate[] chain, String certificates) throws Exception {
		int len = "chain".equals(certificates) ? chain.length : 1;
		StringBuilder ret = new StringBuilder(10000);
		for (int j = 0; j < len; j++) {
			String b64 = DatatypeConverter.printBase64Binary(chain[j].getEncoded());
			int b64Len = b64.length();
			ret.append("-----BEGIN CERTIFICATE-----\n");
			for (int i = 0; i < b64Len; i += 64) {
				int endIdx = i + 64;
				if (endIdx > b64Len)
					endIdx = b64Len;
				ret.append(b64.substring(i, endIdx)).append('\n');
			}
			ret.append("-----END CERTIFICATE-----\n");
		}

		return ret.toString();
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

	// Contains 2 keys (intermediate_requitment and final_recruitment), passwd = test123
	private static final String SELOR_P12 = "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";
}
