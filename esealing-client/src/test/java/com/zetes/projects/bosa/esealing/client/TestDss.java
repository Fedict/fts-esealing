package com.zetes.projects.bosa.esealing.client;

import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import com.zetes.projects.bosa.esealing.dssmodel.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class TestDss {

	public static String DEFAULT_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<note>\n  <mesg>Hello World</mesg>\n</note>";
	public static String BASE_URL = "https://validate.ta.fts.bosa.belgium.be/";

	public static String KEYFILE = "src/test/resources/selor_final.p12";
	public static char[] KEYPWD = "123456".toCharArray();

	public static String PROFILE_NAME = "XADES_1";

	public static boolean DISABLE_NAME_CHECK = false;

	public static void main(String[] args) throws Exception {

		// 0. Get key and cert info
		PrivateKey privKey = null;
		Certificate[] chain = null;
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream(KEYFILE), KEYPWD);
		Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (ks.isKeyEntry(alias)) {
				KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)
					ks.getEntry(alias, new KeyStore.PasswordProtection(KEYPWD));
				privKey = entry.getPrivateKey();
				chain = entry.getCertificateChain();
				break;
			}
		}

		if (DISABLE_NAME_CHECK) {
			javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(new javax.net.ssl.HostnameVerifier() {
				public boolean verify(String s, javax.net.ssl.SSLSession sslSession) {
					return true;
				}
			});
		}

		Client client = new Client(null, null, null, null, null, BASE_URL);

		// 1. Call /getDataToSign
		byte[][] certChain = new byte[chain.length][];
		for (int i = 0; i < chain.length; i++)
			certChain[i] = chain[i].getEncoded();
		byte[] docToSign = DEFAULT_XML.getBytes();
		DataToSignInfo dtsInfo = client.getDataToSign(certChain, docToSign, PROFILE_NAME);
		DataToSignDTO dtsDto = dtsInfo.dataToSignDTO;

ObjectMapper objectMapper = new ObjectMapper();
StringWriter out = new StringWriter();
objectMapper.writeValue(out, dtsDto);
System.out.println("DataToSignDTO:\n" + out.toString() + "\n");

		// 2. Sign the hash
		Signature signat = Signature.getInstance("NoneWithECDSA");
		signat.initSign(privKey);
		signat.update(dtsDto.digest);
		byte[] sigValue = signat.sign();

		// 3. Call /signDocument
		RemoteDocument signedDoc = client.signDocument(dtsInfo.toSignDocument, dtsInfo.clientSignatureParameters, PROFILE_NAME, sigValue);

out = new StringWriter();
objectMapper.writeValue(out, dtsDto);
System.out.println("RemoteDocument:\n" + out.toString() + "\n");
	}
}
