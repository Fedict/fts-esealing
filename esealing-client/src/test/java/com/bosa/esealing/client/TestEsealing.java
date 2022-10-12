package com.bosa.esealing.client;

import java.io.*;
import java.net.*;
import java.util.LinkedHashMap;
import java.util.Enumeration;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;

import com.bosa.esealing.model.*;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSAlgorithm;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.xml.bind.DatatypeConverter;

public class TestEsealing {

	public static String USERNAME = "selor";
	public static char[] PASSWD = "test123".toCharArray();
	//public static String BASE_URL = "http://localhost:8080/";
	public static String BASE_URL = "https://esealing.ta.fts.bosa.belgium.be/";

	public static String HASH_ALGO = "SHA-384";
	public static String HASH_OID = "2.16.840.1.101.3.4.2.2";

	public static String KEYFILE = "src/test/resources/selor_SADSigner.p12";
	public static char[] KEYPWD = "123456".toCharArray();

	public static String XML1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<sample>\nhello1\n</sample>\n";
	public static String XML2 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<sample>\nhello2\n</sample>\n";

	public static void main(String[] args) throws Exception {
		String credentialID = null;

		if (args.length == 0)
			;
		else if (args.length == 1 && !args[0].startsWith("-"))
			credentialID = args[0];
		else {
			System.out.println("You can run without params, or you can specify a 'CredentialID'");
			return;
		}

		Client client = new Client(USERNAME, PASSWD, BASE_URL, KEYFILE, KEYPWD);

		// list()
		ListResponse listResp = client.list();
		dumpListResponse(listResp);

		if (null == credentialID)
			credentialID = listResp.getCredentialIDs()[0];

		// info()
		InfoResponse infoResp = client.info(credentialID);
		dumpInfoResponse(infoResp);

		// signHash()
 		String keyType = infoResp.getKey().getCurve() == null ? "RSA" : "EC";
 		DsvResponse dsvResp = client.signHash(credentialID, new byte[][] {hash(XML1), hash(XML2)}, keyType, HASH_OID);
		dumpDsvResponse(dsvResp);
	}

	public static void dumpListResponse(ListResponse listResp) throws Exception {
		System.out.println("ListResponse: credentials = ");
		String[] creds = listResp.getCredentialIDs();
		String[] certs = listResp.getCertificates();
		for (int i = 0; i < certs.length; i++)
			System.out.println(" - credentialID = " + creds[i] + ", " + getCertInfo(certs[i]));
	}

	public static void dumpInfoResponse(InfoResponse infoResp) throws Exception {
		System.out.println("InfoResponse:");
		Key key = infoResp.getKey();
		System.out.println("  Key: status = " + key.getStatus() + ", key len = " + key.getLen() + ", curve = " + key.getCurve());
		Cert cert = infoResp.getCert();
		System.out.println("  Cert: ");
		System.out.println("    Status: " + cert.getStatus());
		System.out.println("    Valid: " + cert.getValidFrom() + " - " + cert.getValidTo());
		System.out.println("    Subject: " + cert.getSubjectDN());
		System.out.println("    Issuer: " + cert.getIssuerDN());
		System.out.println("    Chain :");
		String[] chain = cert.getCertificates();
		for (int i = 0; i < chain.length; i++)
			System.out.println("     - " + getCertInfo(chain[i]));
		System.out.println("  SCAL: " + infoResp.getSCAL());
	}
	
	public static void dumpDsvResponse(DsvResponse dsvResp) throws Exception {
		System.out.println("DsvResponse:");
		System.out.println("  Policy: " + dsvResp.getPolicy());
		System.out.println("  Signatures (Base64) =");
		String[] sigs = dsvResp.getSignatures();
		for (int i = 0; i < sigs.length; i++) {
			System.out.println("   - " + sigs[i]);
			checkSig(i, DatatypeConverter.parseBase64Binary(sigs[i]), dsvResp);
		}
	}

	private static void checkSig(int idx, byte[] sigVal, DsvResponse dsvResp) throws Exception {
		try {
			String[] certsB64 = dsvResp.getCert().getCertificates();
			X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509")
				.generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(certsB64[0])));
			PublicKey pubKey = cert.getPublicKey();

			String[] parts = HASH_ALGO.split("-");
			String hashAlgo = "";
			for (String p : parts)
				hashAlgo += p;
			String algo = pubKey.getAlgorithm().contains("RSA") ? (hashAlgo + "WithRSA") : (hashAlgo + "WithECDSA");

			byte[] tbs = ((0 == idx) ? XML1 : XML2).getBytes();

			Signature signat = Signature.getInstance(algo);
			signat.initVerify(pubKey);
			signat.update(tbs);
			boolean sigOK = signat.verify(sigVal);
			System.out.println("     Verification " + (sigOK ? "succeeded" : "failed"));
		}
		catch (Exception e) {
			System.out.println("     Verification failed: " + e.toString());
		}
	}

	private static String getCertInfo(String certPem) throws Exception {
		if (null == certPem)
			return "null (???)";
		if (!certPem.startsWith("-----"))
			certPem = "-----BEGIN CERTIFICATE-----\n" + certPem + "\n-----END CERTIFICATE-----";
		java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X509");
		java.security.cert.X509Certificate crt = (java.security.cert.X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certPem.getBytes()));
		return "cert DN = " + crt.getSubjectX500Principal().toString();
	}

	private static byte[] hash(String inp) throws Exception {
		MessageDigest md = MessageDigest.getInstance(HASH_ALGO);
		md.update(inp.getBytes());
		return md.digest();
	}
}
