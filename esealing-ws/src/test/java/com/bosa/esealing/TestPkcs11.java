package com.bosa.esealing;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Enumeration;


public class TestPkcs11 {
	public static void main(String[] args) throws Exception {
		String slotId = null;
		String tokenPin = null;
		if (args.length == 0)
			;
		else if (args.length == 2 && !args[0].startsWith("-")) {
			slotId = args[0];
			tokenPin = args[1];
		}
		else {
			System.out.println("Run without any parameters, or specify a slot ID + the user PIN of that token");
			System.out.println("    E.g. 'selor test123'");
			return;
		}

		if (null == slotId) {
			System.out.println("\nNo slot ID '" + slotId + "' found, exiting");
			return;
		}

	String libLocationName = "SOFTHSM2_CONF";
		String libLocation = System.getenv(libLocationName);
		if (libLocation == null) throw new IOException(libLocationName + " not set !!!!");
		libLocation = libLocation.replaceFirst("etc\\\\.*$", "") +
				(System.getProperty("os.name").toLowerCase().contains("win") ? "lib\\softhsm2-x64.dll" : "lib\\libsofthsm2.so");

		String configText = "--name = HSM\\n"
				+ "library = " + libLocation + "\\n"
				+ "slot = " + slotId + "\\n";

		Provider provider = Security.getProvider("SunPKCS11");
		Provider hsmProvider = provider.configure(configText);
		Security.addProvider(hsmProvider);
		KeyStore hsmKeyStore = KeyStore.getInstance("PKCS11", hsmProvider);
		hsmKeyStore.load(null, tokenPin.toCharArray());
		Enumeration<String> aliases = hsmKeyStore.aliases();

		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (hsmKeyStore.isKeyEntry(alias)) {
				Key key = hsmKeyStore.getKey(alias, "123456".toCharArray());
				Certificate certificate = hsmKeyStore.getCertificateChain(alias)[0];

				String algo = "EC".equals(key.getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA";
				Signature privateSignature = Signature.getInstance(algo);
				privateSignature.initSign((PrivateKey) key);
				byte dataToSign[] = "Lorem Ipsum".getBytes("UTF-8");
				privateSignature.update(dataToSign);
				byte[] s = privateSignature.sign();
				String b64 = Base64.getEncoder().encodeToString(s);

				System.out.println("Signature data from HSM key ('" + algo + "') : " + b64);

				Signature signature1 = Signature.getInstance(algo);
				signature1.initVerify(certificate.getPublicKey());
				signature1.update(dataToSign);
				boolean result = signature1.verify(s);

				System.out.println("Verified with cert from HSM : " + result);
			}
		}
	}
}
