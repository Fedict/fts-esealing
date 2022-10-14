package com.bosa.esealing.client;

import java.io.*;
import java.net.*;
import java.util.LinkedHashMap;
import java.util.Enumeration;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;

// These sources come from 
import com.bosa.esealing.model.*;

import com.bosa.esealing.dssmodel.*;

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

/**
 * Demo client for the demo esealing-ws service.
 * The 'SAD' package (to authorize the use of the esealing key at the esealing service) is
 * in this case a JWS token that is signed with a key on the client side.
 * This can change depending on the TSP that implements the esealing service (e.g. a SAML or
 * an OIDC token that was obtains from an IdP.
 */
public class Client {

	public static String LANG = "en";
	public static String CERTS = "chain"; // options: "none" or "single" (default) or "chain"

	private String esealUser;
	private char[] eSealPwd;
	private String listUrl;
	private String infoUrl;
	private String signHashUrl;

	private String getDtsUrl;
	private String signDocUrl;

	private String sadKeyFile;
	private char[] sadKeyPwd;

	private byte[] lastReq;
	private byte[] lastResp;

	private static boolean DUMP_REQ = true;
	private static boolean DUMP_RESP = true;

	/** Ctor in case a local DSS library is used instead of the getDataToSign() and signDocument() methods to the BOSA DSS */
	public Client(String esealUser, char[] eSealPwd, String esealBaseUrl,
			String sadKeyFile, char[] sadKeyPwd) {
		this(esealUser, eSealPwd, esealBaseUrl, sadKeyFile, sadKeyPwd, null);
	}

	/** Ctor in case the BOSA DSS is used */
	public Client(String esealUser, char[] eSealPwd, String esealBaseUrl,
			String sadKeyFile, char[] sadKeyPwd,
			String dssBaseUrl) {
		this.esealUser = esealUser;
		this.eSealPwd = eSealPwd;
		this.listUrl = esealBaseUrl + "credentials/list";
		this.infoUrl = esealBaseUrl + "credentials/info";
		this.signHashUrl = esealBaseUrl + "signatures/signHash";

		this.sadKeyFile = sadKeyFile;
		this.sadKeyPwd = sadKeyPwd;

		this.getDtsUrl = dssBaseUrl + "signing/getDataToSign";
		this.signDocUrl = dssBaseUrl + "signing/signDocument";
	}

	/**
	 * Request the list of available keys (and certs) from the eSeal TSP.
	 */
	public ListResponse list() throws Exception {
		Boolean certInfo = false;
		Boolean authInfo = false;
		String profile = "http://uri.etsi.org/19432/v1.1.1/certificateslistprotocol#";
		String signerIdentity = null;
		ListRequest listRequest = new ListRequest(getRequestId(), LANG, CERTS, certInfo, authInfo, profile, signerIdentity);

		String jsonReq = serializeToJson(listRequest);
		byte[] respBytes = sendReq(listUrl, jsonReq, true);
		
		ListResponse listResp = (new ObjectMapper()).readValue(respBytes, ListResponse.class);

		return listResp;
	}

	/**
	 * Request the info about a specific key from the eSeal TSP.
	 */
	public InfoResponse info(String credentialID) throws Exception {
		Boolean certInfo = true;
		Boolean authInfo = true;
		String profile = "http://uri.etsi.org/19432/v1.1.1/credentialinfoprotocol#";
		InfoRequest infoRequest = new InfoRequest(getRequestId(), credentialID, LANG, CERTS, certInfo, authInfo, profile);

		String jsonReq = serializeToJson(infoRequest);
		byte[] respBytes = sendReq(infoUrl, jsonReq, true);

		InfoResponse infoResp = (new ObjectMapper()).readValue(respBytes, InfoResponse.class);

		return infoResp;
	}

	/**
	 * Send a document (to be signed) + params to the BOSA DSS service an receive back the hash to be signed
	 */
	public DataToSignInfo getDataToSign(byte[][] certChain, byte[] docToSign, String profileName) throws Exception {
		RemoteDocument toSignDocument = new RemoteDocument(docToSign);
		ClientSignatureParameters clientSignatureParameters = new ClientSignatureParameters(certChain);
		GetDataToSignDTO gdts = new GetDataToSignDTO(toSignDocument, profileName, clientSignatureParameters);

		String jsonReq = serializeToJson(gdts);
		byte[] respBytes = sendReq(getDtsUrl, jsonReq, false);

		DataToSignDTO dataToSignDTO = (new ObjectMapper()).readValue(respBytes, DataToSignDTO.class);

		return new DataToSignInfo(toSignDocument, clientSignatureParameters, profileName, dataToSignDTO);
	}

	/**
	 * Send a hash to the eSeal TSP and receive back a signature
	 */
	public DsvResponse signHash(String credentialID, byte[] digestToSign, String keyType, String digestOID) throws Exception {
		return signHash(credentialID, new byte[][] {digestToSign}, keyType, digestOID);
	}

	/**
	 * Send a hash to the eSeal TSP and receive back a signature
	 */
	public DsvResponse signHash(String credentialID, byte[][] digestsToSign, String keyType, String digestOID) throws Exception {
		String operationMode = "S";
		OptionalData optionalData = new OptionalData(true, true, true, true, true, true);
		Integer validity_period = null;
		Integer numSignatures = new Integer(1);
		String policy = null;
		String signaturePolicyID = null;
		String response_uri = null;
		String signAlgoParams = null;

		// For the test esaling service, these values don't matter: the service select the algo's based on the key type and digest lengths
		String signOID = getSignOID(keyType, digestOID);

		String[] digestsB64 = new String[digestsToSign.length];
		for (int i = 0; i < digestsB64.length; i++)
			digestsB64[i] = DatatypeConverter.printBase64Binary(digestsToSign[i]);
		Digest documentDigests = new Digest(digestsB64, digestOID);

		String SAD = makeSAD(documentDigests);

		DsvRequest dsvRequest = new DsvRequest(operationMode, getRequestId(), SAD, optionalData, validity_period,
			credentialID, LANG, numSignatures, policy, signaturePolicyID, signOID, signAlgoParams, response_uri, documentDigests);

		String jsonReq = serializeToJson(dsvRequest);
		byte[] respBytes = sendReq(signHashUrl, jsonReq, true);
		
		DsvResponse dsvResp = (new ObjectMapper()).readValue(respBytes, DsvResponse.class);

		return dsvResp; 
	}

	/**
	 * Send the unsigned document + parameters + signature value to the BOSA DSS service and receive back signed doc
	 * <br>
	 * NOTE: the docToSign, certChain and profileName must be identical as in the getDataToSign() method!
	 */
	public RemoteDocument signDocument(RemoteDocument toSignDocument, ClientSignatureParameters clientSignatureParameters,
			String profileName, byte[] signatureValue) throws Exception {
		SignDocumentDTO sdDto = new SignDocumentDTO(toSignDocument, profileName, clientSignatureParameters, signatureValue);

		String jsonReq = serializeToJson(sdDto);

		byte[] respBytes = sendReq(signDocUrl, jsonReq, false);

		RemoteDocument signedDoc = (new ObjectMapper()).readValue(respBytes, RemoteDocument.class);

		return signedDoc;
	}

	///////////////////////////////////////////////////////////////////:

	/** Just for debugging */
	public byte[] getLastRequest() {
		return lastReq;
	}

	/** Just for debugging */
	public byte[] getLastResponse() {
		return lastResp;
	}

	///////////////////////////////////////////////////////////////////:

	public static byte[][] pem2CertBytes(String[] certChainB64) throws Exception {
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		byte[][] ret = new byte[certChainB64.length][];
		for (int i = 0; i < ret.length; i++) {
			String b64 = certChainB64[i];
			if (!b64.startsWith("----"))
				b64 = "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----";
			Certificate crt = cf.generateCertificate(new ByteArrayInputStream(b64.getBytes()));
			ret[i] = crt.getEncoded();
		}
		return ret;
	}

	///////////////////////////////////////////////////////////////////:

	protected String getSignOID(String keyType, String digestOID) throws Exception {
		if (null == keyType || keyType.contains("RSA")) {
			if ("1.3.14.3.2.26".equals(digestOID))          return "1.2.840.113549.1.1.5";   // SHA-1
			if ("2.16.840.1.101.3.4.2.1".equals(digestOID)) return "1.2.840.113549.1.1.11";  // SHA256
			if ("2.16.840.1.101.3.4.2.2".equals(digestOID)) return "1.2.840.113549.1.1.12";  // SHA384
			if ("2.16.840.1.101.3.4.2.3".equals(digestOID)) return "1.2.840.113549.1.1.13";  // SHA512
			if ("2.16.840.1.101.3.4.2.4".equals(digestOID)) return "1.2.840.113549.1.1.14";  // SHA224
		}
		else { // ECDSA
			if ("1.3.14.3.2.26".equals(digestOID))          return "1.2.840.113549.1.1.5"; // SHA-1
			if ("2.16.840.1.101.3.4.2.1".equals(digestOID)) return "1.2.840.10045.4.3.2";  // SHA256
			if ("2.16.840.1.101.3.4.2.2".equals(digestOID)) return "1.2.840.10045.4.3.3";  // SHA384
			if ("2.16.840.1.101.3.4.2.3".equals(digestOID)) return "1.2.840.10045.4.3.4";  // SHA512
			if ("2.16.840.1.101.3.4.2.4".equals(digestOID)) return "1.2.840.10045.4.3.1";  // SHA224
		}

		throw new Exception("Unsupported digestOID '" + digestOID + "'");
	}

	protected String getRequestId() {
		return Thread.currentThread().getId() + "" + System.currentTimeMillis() + "" + System.nanoTime();
	}

	/** The SAD = a JWS that contains the documentDigests, signed with the SAD sign key */
	protected String makeSAD(Digest documentDigests) throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream(sadKeyFile), sadKeyPwd);
		Enumeration<String> aliases = ks.aliases();
		PrivateKey sadSignKey = null;
		X509Certificate sadSignCert = null;
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (ks.isKeyEntry(alias)) {
				KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)
					ks.getEntry(alias, new KeyStore.PasswordProtection(sadKeyPwd));
				sadSignKey = entry.getPrivateKey();
				sadSignCert = (X509Certificate) (entry.getCertificateChain())[0];
				break;
			}
		}

		// Serialize the documentDigests to json, this is the JWS header
		String sadData = serializeToJson(documentDigests);

		// Create the JWS header,
		// the kid (key id) value = the certificate serial number, hex encoded (no capitals)
		String sadSigSerialNr = sadSignCert.getSerialNumber().toString(16);
		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.ES384).keyID(sadSigSerialNr).build(),
			new Payload(sadData));

		// Sign the JWS
		jwsObject.sign(new ECDSASigner((ECPrivateKey) sadSignKey));
		String sad = jwsObject.serialize();

		return sad;
	}

	protected String serializeToJson(Object obj) throws Exception {
		ObjectMapper objectMapper = new ObjectMapper();
		StringWriter out = new StringWriter();
		objectMapper.writeValue(out, obj);
		return out.toString();
	}

	protected byte[] sendReq(String endpointUrl, String jsonReq, boolean clientAuth) throws Exception {
		System.out.println("\n\nSending request to: " + endpointUrl);
		if (DUMP_REQ)
			System.out.println("\n" + jsonReq + "\n");

		byte[] req = jsonReq.getBytes();
		lastReq = req;

		URL url = new URL(endpointUrl);
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		if (clientAuth) {
			String basicAuth = DatatypeConverter.printBase64Binary(
				(esealUser + ":" + new String(eSealPwd)).getBytes());
			conn.setRequestProperty("Authorization", "Basic " + basicAuth);
		}
		conn.setRequestMethod("POST");
		conn.setDoOutput(true);
		conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
		conn.getOutputStream().write(req);

		int status = conn.getResponseCode();
		if (status >= 200 && status < 300)
			return readResp(conn.getInputStream());

		byte[] resp = readResp(conn.getErrorStream());
		throw new Exception("Service returned HTTP status " + status +
			(resp.length != 0 ? (": " + new String(resp)) : ""));
	}

	protected byte[] readResp(InputStream is) throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream(10000);
		byte[] buf = new byte[2048];
		int len = is.read(buf);
		while (-1 != len) {
			baos.write(buf, 0, len);
			len = is.read(buf);
		}
		byte[] resp = baos.toByteArray();
		lastResp = resp;

		if (DUMP_RESP)
			System.out.println("\n" + new String(lastResp) + "\n");

		return resp;
	}
}
