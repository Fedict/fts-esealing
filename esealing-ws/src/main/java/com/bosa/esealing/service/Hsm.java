package com.bosa.esealing.service;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAPublicKey;

import java.text.SimpleDateFormat;
import jakarta.xml.bind.DatatypeConverter;

import com.bosa.esealing.exception.ESealException;
import com.bosa.esealing.model.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides fall-back to HsmSoft.java in case HsmPks11.java can't be used.
 * Only for demo purposes, disable HsmSoft (see ALLOW_HSM_SOFT) if you would use this in real situations!
 */
abstract class Hsm {
	/** Set to false if you want to use this in production! */
	public static boolean ALLOW_HSM_SOFT = true;

	protected static final String SCAL = "SCAL1";

	private static final Logger LOG = LoggerFactory.getLogger(Hsm.class);

	private static Hsm hsm;

	protected static SimpleDateFormat sdf = new SimpleDateFormat("YYYYMMDDHHMMSSZ");

	public static Hsm getHsm() throws ESealException {
		if (null == hsm) {
			try {
//				hsm = new StubHsm();
				hsm = new HsmPkcs11();
			}
			catch (Exception e) {
				LOG.error("getHsm(): HsmPkcs11 instantiantion failed: " + e.toString(), e);
				if (ALLOW_HSM_SOFT)
					hsm = new StubHsm();
				else
					throw new ESealException(500, "HSM not available", e.getMessage());
			}
		}

		return hsm;
	}

	public abstract ListResponse getCredentialsList(String userName, char[] userPwd, String certificates) throws ESealException;

	public abstract InfoResponse getCredentialsInfo(String userName, char[] userPwd, String keyName, String returnCerts,
			Boolean getCertInfo, Boolean getAuthInfo) throws ESealException;

	public abstract DsvResponse signHash(String userName, char[] userPwd, String keyName, OptionalData optionalData,
			String signAlgo, Digest documentDigests) throws ESealException;

	// Get the cert with the specified serialNumber
	public abstract X509Certificate getSadSigningCert(String userName, char[] userPwd, String serialNumber) throws ESealException;

	protected String convertCerts(Certificate[] chain, String certificates) throws Exception {
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

	protected InfoResponse makeInfoResponse(Certificate[] chain, String returnCerts, Boolean getCertInfo, Boolean getAuthInfo) throws Exception {
		boolean needCertAndKeyInfo = Boolean.TRUE.equals(getCertInfo);

		Cert cert = needCertAndKeyInfo ? makeCertInfo(chain, returnCerts) : null;

		Key key = needCertAndKeyInfo ? makeKeyInfo(chain[0]) : null;

		Boolean multisign = Boolean.TRUE;

		String authMode = Boolean.TRUE.equals(getAuthInfo) ? SADChecker.getInstance().getAuthMode() : null;

		return new InfoResponse(cert, key, multisign, "OK", null, authMode, SCAL);
	}

	protected Cert makeCertInfo(Certificate[] chain, String returnCerts) throws Exception {
		X509Certificate signingCert = (X509Certificate) chain[0];

		String status = System.currentTimeMillis() < signingCert.getNotAfter().getTime() ? "valid" : "expired";

		String[] certificates = null;
		if (!"none".equals(returnCerts)) {
			int len = "chain".equals(returnCerts) ? chain.length : 1;
			certificates = new String[len];
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

	protected Key makeKeyInfo(Certificate signingCert) throws Exception {
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

	protected DsvResponse makeDsvResponse(OptionalData optData, Certificate[] chain, String[] sigs, String POLICY, String SIG_POLICY_ID) throws Exception {
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
}
