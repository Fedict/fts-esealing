package com.zetes.projects.bosa.esealing.service;

import com.zetes.projects.bosa.esealing.exception.ESealException;
import com.zetes.projects.bosa.esealing.model.DsvRequest;
import com.zetes.projects.bosa.esealing.model.Digest;

import java.security.cert.X509Certificate;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import net.minidev.json.JSONObject;
import net.minidev.json.JSONArray;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Checks the SAD (authentication data) in a 'signHash' request.
 * In this case, the SAD is a JWS (a signed JSON) that contains the hashes to be signed.
 * Only the hashes found in this SAD are signed.
 * The certificate to verify the SAD JWS must be present in the HSM token that corresponds with this 'userName',
 * the 'kid' value in the JWS must be the hex dump of the certificate serial number.
 */
class SADChecker {
	private static final Logger LOG = LoggerFactory.getLogger(Hsm.class);

	private static SADChecker sadChecker = null;

	public static SADChecker getInstance() {
		if (null == sadChecker)
			sadChecker = new SADChecker();
		return sadChecker;
	}

	private SADChecker() {
	}

	public String getAuthMode() {
		return "identificationToken";
	}

	public void checkDsv(String userName, char[] userPwd, DsvRequest dsvRequest) throws ESealException {
		LOG.info("Checking SAD list...");

		try {
			// Parse the SAD (which is a JWT/JWS)
			String sadStr = dsvRequest.getSAD();
			JWSObject sad = JWSObject.parse(sadStr);

			// Get the 'kit' value from the header, this should be the SAD signing cert serial number
			JWSHeader sadHeader = sad.getHeader();
			String kid = sadHeader.getKeyID();

			// Look up the SAD signing cert in the HSM
			X509Certificate sadSigningCert = Hsm.getHsm().getSadSigningCert(userName, userPwd, kid);
			PublicKey sadSigningPubKey = sadSigningCert.getPublicKey();
			LOG.info("  Searched for kid = " + kid + ", found cert with serialnr = " + sadSigningCert.getSerialNumber().toString(16));

			///////////////////////////////////////////////////////////////////////////////////////////////////
			// We don't do any check on the cert, we assume that it's presence on the HSM means that it's OK //
			///////////////////////////////////////////////////////////////////////////////////////////////////

			// Verify the SAD signature
			JWSVerifier verifier = sadSigningPubKey.getAlgorithm().contains("EC") ?
				new ECDSAVerifier((ECPublicKey) sadSigningPubKey) : 
				new RSASSAVerifier((RSAPublicKey) sadSigningPubKey);
			boolean sigOK = sad.verify(verifier);
			if (!sigOK)
				throw new ESealException(402, "Bad SAD", "Verification of the SAD signature failed");

			// Check that the data (= 'payload') in the SAD contains the same hash algo OID
			// and the same hashes as in the "digests" part of the DsvRequest

			JSONObject sadData = sad.getPayload().toJSONObject();
			// Example of sadData:
			// {"hashes":["jyFiAqEDvida22dGkSAIQPEoOye5zdAg6hLZGHW9DD+pd4UDHATnUOQ+CLebINkx","nc439C7P7kr3+V\/eYzar+A3HtSAzjXn85HgCqIzWHF0J3L2ygPbkJFUWdHUiLpsq"],"hashAlgorithmOID":"2.16.840.1.101.3.4.2.2"}

			// Get the "digests" from the DsvRequest
			Digest digest = dsvRequest.getDocumentDigests();
			String hashAlgOidInReq = digest.getHashAlgorithmOID();
			String[] hashesInReq = digest.getHashes();
			int hashesInReqLen = hashesInReq.length;

			// Check the hash algo OID in the SAD
			String hashAlgOidInSAD = (String) sadData.get("hashAlgorithmOID");
			if (!hashAlgOidInReq.equals(hashAlgOidInSAD))
				throw new ESealException(402, "Wrong hash algo OID in SAD", hashAlgOidInSAD);
			
			// Check the hashes in the SAD
			JSONArray hashesInSAD = (JSONArray) sadData.get("hashes");
			int hashesInSADCount = hashesInSAD.size();
			for (int j = 0; j < hashesInReqLen; j++) {
				boolean found = false;
				for (int i = 0; !found && i < hashesInSADCount; i++) {
					if (hashesInReq[j].equals((String) hashesInSAD.get(i)))
						found = true;
				}
				if (!found)
					throw new ESealException(402, "Missing hash in SAD", hashesInReq[j]);
			}

			LOG.info("  Successfully checked " + hashesInReqLen + " hashes");
		}
		catch (ESealException e) {
			throw e;
		}
		catch (Exception e) {
			LOG.error("SADChecker.checkDsv(): " + e.toString(), e);
			throw new ESealException(500, "Bad SAD", "Error parsing/verifying SAD: " + e.getMessage());
		}
	}
}
