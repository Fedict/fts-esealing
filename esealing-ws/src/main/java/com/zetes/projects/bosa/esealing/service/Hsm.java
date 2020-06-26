package com.zetes.projects.bosa.esealing.service;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.io.ByteArrayInputStream;
import java.util.Enumeration;
import java.util.Vector;
import javax.xml.bind.DatatypeConverter;

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
public class Hsm {

	private static Hsm hsm;

	public static Hsm getHsm() {
		if (null == hsm)
			hsm = new Hsm();
		return hsm;
	}

	////////////////////////////////////////////////////////

	private Hsm() {
	}

	public ListResponse getCredentialsList(String userName, char[] userPwd, String certificates) {
		try {
			KeyStore ks = getKeyStore(userName, userPwd);

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
			e.printStackTrace();
			return null; // TODO
		}
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

	private KeyStore getKeyStore(String userName, char[] userPwd) throws Exception {
		String p12Str = null;
		if ("bosa".equals(userName))
			p12Str = BOSA_P12;
		else
			; // TODO

		KeyStore ks = KeyStore.getInstance("PKCS12");
		byte[] p12Bytes = DatatypeConverter.parseBase64Binary(p12Str);
		ks.load(new ByteArrayInputStream(p12Bytes), userPwd);
		
		return ks;
	}

	////////////////////////////////////////////////////////

	// Contains 2 keys (sam and inge), passwd = 123456
	private static final String BOSA_P12 = "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";
}
