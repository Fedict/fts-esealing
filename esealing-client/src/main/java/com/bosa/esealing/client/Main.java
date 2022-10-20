package com.bosa.esealing.client;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;

import com.bosa.esealing.model.ListResponse;
import com.bosa.esealing.model.InfoResponse;
import com.bosa.esealing.model.DsvResponse;
import com.bosa.esealing.dssmodel.*;
import com.bosa.esealing.model.*;
import jakarta.xml.bind.DatatypeConverter;

/** Command line program to demo the esaling process. <br>
 *  There are 2 services involved: <br>
 *  - The esealing service: list credentals, get info about a credential, sign (a) hash value(s) <br>
 *  - The BOSA DSS service: get data to sign (= hash value), sign document <br>
 *  The calls to the BOSA DSS service could be replaced by function calls to the DSS library
 *  (https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/DSS+Cookbook)
 */
public class Main {

	private static String esealBaseUrl = "https://esealing.ta.fts.bosa.belgium.be:443/esealing/";

	// Connection params for the BOSA DSS service
	private static String dssBaseUrl = "http://validate.ta.fts.bosa.belgium.be:443/signandvalidation/";

	public static void usage(String msg) {
		if (null != msg)
			System.out.println(msg);
		else {
			System.out.println("Command line esealing demo client.");
			System.out.println("  Communicates with an esealing and the BOSA DSS service");
		}
		System.out.println("Parameters:");
		System.out.println("  -u   : eseal username (default: selor)");
		System.out.println("  -p   : eseal password (default: test123)");
		System.out.println("  -eh  : eseal hostname (default: localhost)");
		System.out.println("  -ep  : eseal port (default: 8080)");
		System.out.println("  -kf  : SAD keyfile (default: src/test/resources/selor_SADSigner.p12)");
		System.out.println("  -kp  : SAD password (default: 123456)");
		System.out.println("  -dh  : BOSA DSS hostname (default: localhost)");
		System.out.println("  -dp  : BOSA DSS port (default: 8080)");
	}

	public static void main(String[] args) throws Exception {

		esealBaseUrl = "http://localhost:8752/";
		dssBaseUrl = "http://localhost:8751/";

		byte[] xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<note>\n  <mesg>Hello World</mesg>\n</note>".getBytes();
		String PROFILE_NAME = "XADES_1";

		// Connection params for the esealing TSP
		String esealUser = "sealing";
		char[] eSealPwd = "123456".toCharArray();

		String keyFile = "esealing-client/src/test/resources/sealing_sad.p12";
		char[] keyPwd = "123456".toCharArray();

		// Which key on the esealing TSP to use
		String credentialID = null;
	
		// Parse command line params
		int argc = args.length;
		if (1 == (argc % 2)) {
			usage(null);
			return;
		}
		for (int i = 0; i < argc; i += 2) {
			String c = args[i];
			if (c.equals("-u"))
				esealUser = args[i + 1];
			else if (c.equals("-p"))
				eSealPwd = args[i + 1].toCharArray();
			else if (c.equals("-eu"))
				esealBaseUrl = args[i + 1];
			else if (c.equals("-kf"))
				keyFile = args[i + 1];
			else if (c.equals("-kp"))
				keyPwd = args[i + 1].toCharArray();
			else if (c.equals("-du"))
				dssBaseUrl = args[i + 1];
			else {
				usage("Unknown parameter '" + c + "'");
				return;
			}
		}

		// Disable hostname check if needed
		javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(new javax.net.ssl.HostnameVerifier() {
			public boolean verify(String s, javax.net.ssl.SSLSession sslSession) {
				return true;
			}
		});

		Client client = new Client(esealUser, eSealPwd, esealBaseUrl, keyFile, keyPwd, dssBaseUrl);

		// 1. To the esealing service: list credentials (optional)
		ListResponse listResp = client.list();
		dumpListResponse(listResp);

		if (null == credentialID)
			credentialID = listResp.getCredentialIDs()[0];

		// 2. To the esealing service: info about the selected credential (optional)
		InfoResponse infoResp = client.info(credentialID);
		dumpInfoResponse(infoResp);

		// 3. To the BOSA DSS service: get data to sign
		String chainB64[] = infoResp.getCert().getCertificates();
		byte[][] certChain = new byte[chainB64.length][];
		for (int i = 0; i < chainB64.length; i++)
			certChain[i] = DatatypeConverter.parseBase64Binary(chainB64[i]);
		byte[] docToSign = xml;
		DataToSignInfo dataToSignInfo = client.getDataToSign(certChain, docToSign, PROFILE_NAME);
		DataToSignDTO dtsDto = dataToSignInfo.dataToSignDTO;
		dumpGetDataToSignResponse(dtsDto);

		// 4. To the esealing service: sign hash value(s)
 		String keyType = infoResp.getKey().getCurve() == null ? "RSA" : "EC";
 		String hashOID = dtsDto.digestAlgorithm.oid;
		DsvResponse dsvResp = client.signHash(credentialID, dtsDto.digest, keyType, hashOID);
		dumpDsvResponse(dtsDto.digest, dsvResp);

		// 5. To the BOSA DSS service: sign document
		//  ***   Note: toSignDocument, clientSignatureParameters and profileName _must_ be    ***
		//  ***   the same as in the previous call (in step 3)                                 ***

		dataToSignInfo.clientSignatureParameters.signingDate = dtsDto.getSigningDate();
		byte[] sigValue = DatatypeConverter.parseBase64Binary(dsvResp.getSignatures()[0]);
		RemoteDocument signedDoc2 = client.signDocument(dataToSignInfo.toSignDocument,
			dataToSignInfo.clientSignatureParameters, dataToSignInfo.profileName, sigValue);
	}

	public static void dumpListResponse(ListResponse listResp) throws Exception {
		System.out.println("1. ListResponse: credentials = ");
		String[] creds = listResp.getCredentialIDs();
		String[] certs = listResp.getCertificates();
		for (int i = 0; i < certs.length; i++)
			System.out.println(" - credentialID = " + creds[i] + ", " + getCertInfo(certs[i]));
	}

	public static void dumpInfoResponse(InfoResponse infoResp) throws Exception {
		System.out.println("2. InfoResponse:");
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

	public static void dumpGetDataToSignResponse(DataToSignDTO dtsDto) throws Exception {
		System.out.println("3. DataToSign response:");
		System.out.println("  Digest algo: " + dtsDto.digestAlgorithm);
		System.out.println("  Digest value (Base64): " + DatatypeConverter.printBase64Binary(dtsDto.digest));
	}

	public static void dumpDsvResponse(byte[] digest, DsvResponse dsvResp) throws Exception {
		System.out.println("4. DsvResponse:");
		System.out.println("  Policy: " + dsvResp.getPolicy());
		System.out.println("  Signature (Base64):");
		String[] sigs = dsvResp.getSignatures();
		String sig = sigs[0];
		System.out.println("     " + sig.substring(0, 8) + " ... " + sig.substring(sig.length() - 8));
		checkSig(digest, DatatypeConverter.parseBase64Binary(sigs[0]), dsvResp);
	}

	private static void checkSig(byte[] digest, byte[] sigVal, DsvResponse dsvResp) throws Exception {
		try {
			String[] certsB64 = dsvResp.getCert().getCertificates();
			X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509")
				.generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(certsB64[0])));
			PublicKey pubKey = cert.getPublicKey();

			if (pubKey.getAlgorithm().contains("EC")) {
				Signature signat = Signature.getInstance("NONEWithECDSA");
				signat.initVerify(pubKey);
				signat.update(digest);
				boolean sigOK = signat.verify(sigVal);
				System.out.println("     Verification " + (sigOK ? "succeeded" : "failed"));
			}
			else {
				// For RSA, there is no PKCS1WithRSA algorithm so we have to do a 'manual' verification
				RSAPublicKey rsaPub = (RSAPublicKey) pubKey;
				BigInteger s = new BigInteger(1, sigVal);
				BigInteger d = rsaPub.getPublicExponent();
				BigInteger m = rsaPub.getModulus();
				byte[] res = s.modPow(d, m).toByteArray();
				boolean sigOK = arrayCmp(res, res.length - digest.length, digest, 0, digest.length);
				if (sigOK)
					System.out.println("     Verification succeeded");
				else {
					if (0 == res[0] && (byte) 0xff == res[1] && (byte) 0xff == res[2] && (byte) 0xff == res[3])
						System.out.println("     Verification failed (bad hash)");
					else
						System.out.println("     Verification failed (wrong pubkey/cert or bad sigvalue)");
				}
			}
		}
		catch (Exception e) {
			System.out.println("     Verification failed: " + e.toString());
		}
	}

	private static boolean arrayCmp(byte[] a, int aOffs, byte[] b, int bOffs, int len) {
		for (int i = 0; i < len; i++) {
			if (a[aOffs + i] != b[bOffs + i])
				return false;
		}
		return true;
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
}
