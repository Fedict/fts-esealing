package com.bosa.esealing.service;

import java.io.IOException;
import java.util.HashMap;
import java.util.Collection;
import java.util.Vector;
import java.util.Set;
import java.math.BigInteger;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

import com.bosa.esealing.exception.ESealException;
import com.bosa.esealing.model.*;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.objects.GenericTemplate;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.ECPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.BooleanAttribute;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import org.apache.tomcat.util.buf.HexUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Access to the HSM. <br>
 * Many server signing application seem to store the signature keys in a database, encrypted by a master key in the HSM.
 * However to avoid a database and cut development costs, we decided another approach: each "customer" is given a slot
 * on the HSM that contains the keys for this customer. <br>
 * As the calls to this service as based on a username and password, the following mapping is done:
 * <pre>
 *   username        = HSM slot label
 *   userPwd         = HSM slot 'PIN'
 *   credentialID    = the label of a key within this HSM slot
 * </pre>
 * Apart from the signing keys and certificate chains, the HSM slot must also contain the 'SAD certificate' that must
 * be used to verify the SAD data (see SADChecker.java)
 */
class HsmPkcs11 extends Hsm {
	public static String DOCKER_PKCS11_PATH = "/usr/lib/softhsm/libsofthsm2.so";

	private static Module module;

	private static HashMap<String, HsmTokenInfo> tokens = new HashMap<String, HsmTokenInfo>(20);

	private static final Logger LOG = LoggerFactory.getLogger(HsmPkcs11.class);

	private static final String POLICY = "Just for testing, should add a real HSM";
	private static final String SIG_POLICY_ID = "Test signatures on (soft) HSM";

	protected HsmPkcs11() throws Exception {

		String libLocation;
		if (System.getProperty("os.name").toLowerCase().contains("win")) {
			String libLocationName = "SOFTHSM2_CONF";
			libLocation = System.getenv(libLocationName);
			if (libLocation == null) throw new IOException(libLocationName + " not set !!!!");
			libLocation = libLocation.replaceFirst("etc\\\\.*$", "") + "lib\\softhsm2-x64.dll";
			LOG.debug("Loading PKCS11 Library from system property '" + libLocationName + "' : " + libLocation);
		} else {
			libLocation = DOCKER_PKCS11_PATH;
		}
		LOG.debug("Loading PKCS11 Library from  '" + libLocation + "'");
		module = Module.getInstance(libLocation);

		module.initialize(null);
	}

	public ListResponse getCredentialsList(String userName, char[] userPwd, String certificates) throws ESealException {
		HsmTokenInfo hsmTokenInfo = getTokenInfo(userName, userPwd);

		try {
			Set<String> credIdSet = hsmTokenInfo.keys.keySet();
			int keyCount = credIdSet.size();
			String[] credIdArr = credIdSet.toArray(new String[keyCount]);

			String[] certArr = new String[keyCount];
			for (int i = 0; i < keyCount; i++) {
				HsmKeyInfo hsmKeyInfo = hsmTokenInfo.keys.get(credIdArr[i]);
				certArr[i] = convertCerts(hsmKeyInfo.chain, certificates);
			}

			return new ListResponse("OK", null, credIdArr, certArr);
		}
		catch (Exception e) {
			LOG.error("getCredentialsList(" + userName + "): " + e.toString(), e);
			throw new ESealException(500, "Internal error", e.getMessage());
		}
		finally {
			closeSession(hsmTokenInfo);
		}
	}

	public InfoResponse getCredentialsInfo(String userName, char[] userPwd, String keyName, String returnCerts,
			Boolean getCertInfo, Boolean getAuthInfo) throws ESealException {
		HsmTokenInfo hsmTokenInfo = getTokenInfo(userName, userPwd);

		HsmKeyInfo hsmKeyInfo = hsmTokenInfo.keys.get(keyName);
		if (null == hsmKeyInfo)
			throw new ESealException(404, "Not found", "CredentialID ('" + keyName + "') not found");

		try {
			return makeInfoResponse(hsmKeyInfo.chain, returnCerts, getCertInfo, getAuthInfo);
		}
		catch (Exception e) {
			LOG.error("getCredentialsList(" + userName + "): " + e.toString(), e);
			throw new ESealException(500, "Internal error", e.getMessage());
		}
		finally {
			closeSession(hsmTokenInfo);
		}
	}

	public DsvResponse signHash(String userName, char[] userPwd, String keyName, OptionalData optionalData,
			String signAlgo, Digest documentDigests) throws ESealException {
		HsmTokenInfo hsmTokenInfo = getTokenInfo(userName, userPwd);

		HsmKeyInfo hsmKeyInfo = hsmTokenInfo.keys.get(keyName);
		if (null == hsmKeyInfo)
			throw new ESealException(404, "Not found", "CredentialID ('" + keyName + "') not found");

		PrivateKey privKey = getPrivKey(hsmTokenInfo.session, hsmKeyInfo);
		try {
			String[] hashes = documentDigests.getHashes();
			String[] sigs = new String[hashes.length];

			for (int i = 0; i < hashes.length; i++) {
				byte[] hash = Base64.decodeBase64(hashes[i]);
				byte[] sig = doSign(hsmTokenInfo.session, privKey, hash);
				sigs[i] = Base64.encodeBase64String(sig);
			}

			return makeDsvResponse(optionalData, hsmKeyInfo.chain, sigs, POLICY, SIG_POLICY_ID);
		}
		catch (Exception e) {
			LOG.error("getCredentialsList(" + userName + "): " + e.toString(), e);
			throw new ESealException(500, "Internal error", e.getMessage());
		}
		finally {
			closeSession(hsmTokenInfo);
		}
	}

	public X509Certificate getSadSigningCert(String userName, char[] userPwd, String serialNumber) throws ESealException {
		HsmTokenInfo hsmTokenInfo = getTokenInfo(userName, userPwd);

		try {
			for (int i = 0; i < hsmTokenInfo.certs.length; i++) {
				if (hsmTokenInfo.certs[i].getSerialNumber().toString(16).equals(serialNumber))
					return hsmTokenInfo.certs[i];
			}
		}
		catch (Exception e) {
			LOG.error("Hsm.getSadSigningCert(): " + e.toString(), e);
			throw new ESealException(500, "Internal error", e.getMessage());
		}
		finally {
			closeSession(hsmTokenInfo);
		}

		LOG.error("HSM.getSadSigningCert(): no certificate found with serialNumber = " + serialNumber);
		throw new ESealException(404, "Not found", "SAD signing certificate not found");
	}

	/**
	 * The first time this method is called for the 'userName', the corresponding token is read
	 *  and the info is put in an HsmTokenInfo object that is stored in the 'tokens' map.
	 *  The next times, this HsmTokenInfo is just retreived from the 'tokens' map and only a login is done
	 *  to check that the userPwd (= the slot PIN) is correct.
	 */
	private HsmTokenInfo getTokenInfo(String userName, char[] userPw) throws ESealException {
		HsmTokenInfo tokenInfo = tokens.get(userName);

		if (null == tokenInfo)
			tokenInfo = initTokenInfo(userName, userPw);
		else
			tokenInfo.session = loginToken(tokenInfo.token, userName, userPw);

		return tokenInfo;
	}

	private HsmTokenInfo initTokenInfo(String userName, char[] userPwd)  throws ESealException {
		Slot[] slots = null;
		try {
			slots = module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
		}
		catch (Exception e) {
			LOG.error("Module.getSlotList(): " + e.toString(), e);
			throw new ESealException(500, "HSM error", e.getMessage());
		}
		if (null == slots || slots.length == 0) {
			LOG.info("Module.getSlotList() didn't return any slots");
			throw new ESealException(500, "Empty HSM", "No keys found");
		}

		Token token = null;
		try {
			for (Slot slot : slots) {
				Token t = slot.getToken();
				TokenInfo ti = t.getTokenInfo();
				String label = ti.getLabel().trim();
				if (label.equals(userName)) {
					token = t;
					break;
				}
			}
		}
		catch (Exception e) {
			LOG.error("Slot.getToken() or token.getTokenInfo(): " + e.toString(), e);
			throw new ESealException(500, "HSM error", e.getMessage());
		}
		if (null == token) {
			LOG.info("No slot named '" + userName + "' found in Module.getSlotList()");
			throw new ESealException(401, "Bad Authorization", "Bad username/password");
		}

		Session session = loginToken(token, userName, userPwd);

		HsmTokenInfo hsmTokenInfo = makeTokenInfo(token, session);

		tokens.put(userName, hsmTokenInfo);

		LOG.info("Added HSM token info for '" + userName + "': " + hsmTokenInfo.keys.size() +
			" keys and " + hsmTokenInfo.certs.length + " certs");

		return hsmTokenInfo;
	}

	private HsmTokenInfo makeTokenInfo(Token token, Session session) throws ESealException {
		PKCS11Object[] objects = null;
		try {
			session.findObjectsInit(new GenericTemplate());
			objects = session.findObjects(50);
			session.findObjectsFinal();
		}
		catch (Exception e) {
			LOG.error("Slot.getToken() or token.getTokenInfo(): " + e.toString(), e);
			throw new ESealException(500, "HSM error", e.getMessage());
		}
		if (null == objects || objects.length == 0) {
			LOG.info("findObjects() returned null or empty, exiting");
			return new HsmTokenInfo(token, session, new HashMap<String, HsmKeyInfo>(0), new X509Certificate[0]);
		}

		HashMap<ByteArrayAttribute, X509Certificate> certMap = getCerts(objects);
		Collection<X509Certificate> coll = certMap.values();
		X509Certificate[] certs = new X509Certificate[coll.size()];
		coll.toArray(certs);

		HashMap<String, HsmKeyInfo> keys = getKeys(objects, certMap, certs);

		return new HsmTokenInfo(token, session, keys, certs);
	}

	private HashMap<ByteArrayAttribute, X509Certificate> getCerts(PKCS11Object[] p11Objects) throws ESealException {
		try {
			HashMap<ByteArrayAttribute, X509Certificate> ret = new HashMap<ByteArrayAttribute, X509Certificate>(50);

			CertificateFactory cf = CertificateFactory.getInstance("X509");

			for (PKCS11Object obj : p11Objects) {
				if (obj instanceof X509PublicKeyCertificate) {
					X509PublicKeyCertificate c = (X509PublicKeyCertificate) obj;
					X509Certificate cert = (X509Certificate) cf.generateCertificate(
						new ByteArrayInputStream(c.getValue().getByteArrayValue()));
					ret.put(c.getId(), cert);
				}
			}

			return ret;
		}
		catch (Exception e) {
			LOG.error("Failed to read X509 cert: " + e.toString(), e);
			throw new ESealException(500, "HSM error", e.getMessage());
		}
	}

	private HashMap<String, HsmKeyInfo> getKeys(PKCS11Object[] p11Objects,
			HashMap<ByteArrayAttribute, X509Certificate> certMap, X509Certificate[] certs) throws ESealException {
		try {
			HashMap<String, HsmKeyInfo> ret = new HashMap<String, HsmKeyInfo>(50);

			for (PKCS11Object obj : p11Objects) {
				if (obj instanceof PrivateKey) {
					PrivateKey privKey = (PrivateKey) obj;
					String label = new String(privKey.getLabel().getCharArrayValue());
					X509Certificate cert = certMap.get(privKey.getId());
					if (null == cert) {
						LOG.info("No cert found corresponding with (= having the same ID as) key " + label);
						continue;
					}

					HsmKeyInfo hsmKeyInfo = makeHsmKeyInfo(privKey, cert, certMap, certs);
					LOG.info("  - Created key info with ID = "
						+ HexUtils.toHexString(privKey.getId().getByteArrayValue())
						+ " and label = " + label);

					ret.put(label, hsmKeyInfo);
				}
			}

			return ret;
		}
		catch (Exception e) {
			LOG.error("Failed to read X509 cert: " + e.toString(), e);
			throw new ESealException(500, "HSM error", e.getMessage());
		}
	}

	private HsmKeyInfo makeHsmKeyInfo(PrivateKey privKey, X509Certificate cert,
			HashMap<ByteArrayAttribute, X509Certificate> certMap, X509Certificate[] certs) {
		// Build the cert chain
		Vector<X509Certificate> chain = new Vector<X509Certificate>(5);
		boolean doContinue = true;
		int maxLen = certs.length;
		for (int i = 0; i < maxLen && null != cert; i++) {
			chain.add(cert);
			X500Principal subjDn = cert.getSubjectX500Principal();
			X500Principal issuerDn = cert.getIssuerX500Principal();
			if (subjDn.equals(issuerDn))
				break;
			else {
				X509Certificate issuerCert = null;
				for (int j = 0; j < certs.length; j++) {
					if (issuerDn.equals(certs[j].getSubjectX500Principal())) {
						issuerCert = certs[j];
						break;
					}
				}
				cert = issuerCert;
			}
		}

		X509Certificate[] ch = new X509Certificate[chain.size()];
		chain.toArray(ch);

		return new HsmKeyInfo(privKey.getId().getByteArrayValue(), ch);
	}

	private PrivateKey getPrivKey(Session session, HsmKeyInfo hsmKeyInfo) throws ESealException {
		PKCS11Object[] objs = null;
		try {
			GenericTemplate templ = new GenericTemplate();
			BooleanAttribute signAttribute = new BooleanAttribute(Attribute.SIGN);
			signAttribute.setBooleanValue(Boolean.TRUE);
			templ.addAttribute(signAttribute);
			ByteArrayAttribute idAttribute = new ByteArrayAttribute(Attribute.ID);
			idAttribute.setByteArrayValue(hsmKeyInfo.id);
			templ.addAttribute(idAttribute);

			session.findObjectsInit(templ);
			objs = session.findObjects(1);
			session.findObjectsFinal();
		}
		catch (Exception e) {
			LOG.error("getPrivKey(): " + e.toString(), e);
			throw new ESealException(500, "Internal error", e.getMessage());
		}

		if (null == objs || objs.length != 1) {
			LOG.error("getPrivKey(): could not find back private key");
			throw new ESealException(500, "Internal error", "Could not find back private key");
		}

		if (!(objs[0] instanceof PrivateKey)) {
			LOG.error("getPrivKey(): found object is no PrivateKey instance but: " + objs[0].getClass().toString());
			throw new ESealException(500, "Internal error", "Unexpected key type");
		}

		return (PrivateKey) objs[0];
	}

	private byte[] doSign(Session session, PrivateKey privKey, byte[] hashVal) throws Exception {
		if (privKey instanceof ECPrivateKey) {
			LOG.info("Making EC signature, key ID = " + HexUtils.toHexString(privKey.getId().getByteArrayValue()));
			ECPrivateKey ecKey = (ECPrivateKey) privKey;

			session.signInit(new Mechanism(PKCS11Constants.CKM_ECDSA), ecKey);
			byte[] sigVal = session.sign(hashVal);

			// Convert from PKCS11 signature format (R and S values concatenated)
			// to X509 signature format (a SEQUENCE of 2 INTEGERs in ASN.1 DER encoding)
			byte[] r = new byte[sigVal.length / 2];
			byte[] s = new byte[sigVal.length / 2];
			System.arraycopy(sigVal, 0, r, 0, r.length);
			System.arraycopy(sigVal, r.length, s, 0, s.length);
			sigVal = GenDer.make(0x30, new byte[][] {
				GenDer.make(0x02, (new BigInteger(1, r)).toByteArray()),
				GenDer.make(0x02, (new BigInteger(1, s)).toByteArray()),
			});

			return sigVal;
		}
		else if (privKey instanceof RSAPrivateKey) {
			LOG.info("Making RSA signature");
			RSAPrivateKey rsaKey = (RSAPrivateKey) privKey;

			byte[] hashAID = getAID(hashVal.length);

			byte[] sigInp = new byte[hashAID.length + hashVal.length];
			System.arraycopy(hashAID, 0, sigInp, 0, hashAID.length);
			System.arraycopy(hashVal, 0, sigInp, hashAID.length, hashVal.length);

			session.signInit(new Mechanism(PKCS11Constants.CKM_RSA_PKCS), rsaKey);
			byte[] sigVal = session.sign(sigInp);

			return sigVal;
		}
		else
			throw new Exception("\nCan't sign with key '" + privKey.getLabel() + ": not supported");
	}

	private byte[] getAID(int hashLenBytes) throws Exception {
		switch(hashLenBytes) {
			case 20: return SHA1_AID;
			case 32: return SHA256_AID;
			case 48: return SHA384_AID;
			case 64: return SHA512_AID;
			default: throw new Exception("Unsupport hash length of " + hashLenBytes + " bytes");
		}
	}

	private Session loginToken(Token token, String tokenLabel, char[] tokenPin) throws ESealException {
		Session session = null;
		try {
			boolean rwSession = false;
			session = token.openSession(Token.SessionType.SERIAL_SESSION, rwSession, null, null);
		}
		catch (Exception e) {
			LOG.error("Couldn't open session to token '" + tokenLabel + "': " + e.toString(), e);
			throw new ESealException(500, "Could not open HSM session", e.getMessage());
		}

		try {
			session.login(Session.UserType.USER, tokenPin);
		}
		catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception e) {
			String mesg = e.getMessage();
			if (!mesg.contains("CKR_USER_ALREADY_LOGGED_IN")) {
				LOG.error("session.login(): " + e.toString(), e);
				closeSession(session);
				throw new ESealException(401, "Bad Authorization", "Bad username/password");
			}
		}
		catch (Exception e) {
			LOG.error("Couldn't open session to token '" + tokenLabel + "': " + e.toString(), e);
			closeSession(session);
			throw new ESealException(500, "Could not login on HSM session", e.getMessage());
		}

		return session;
	}

	private void closeSession(HsmTokenInfo tokenInfo) {
		if (null == tokenInfo || null == tokenInfo.session)
			return;
		closeSession(tokenInfo.session);
		tokenInfo.session = null;
	}

	private void closeSession(Session session) {
		if (null == session)
			return;
		try {
			session.logout();
		}
		catch (Exception e) {
			LOG.error("session.logout() failed: " + e.toString(), e);
		}
		try {
			session.closeSession();
		}
		catch (Exception e) {
			LOG.error("session.closeSession() failed: " + e.toString(), e);
		}
	}

        private static final byte SHA1_AID[] = {
                0x30, 0x21,
                0x30, 0x09,
                0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
                0x05, 0x00,
                0x04, 0x14
        };
        private static final byte SHA256_AID[] = {
                0x30, 0x31,
                0x30, 0x0d,
                0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                        0x01,
                0x05, 0x00,
                0x04, 0x20
        };
        private static final byte SHA384_AID[] = {
                0x30, 0x41,
                0x30, 0x0d,
                0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                        0x02,
                0x05, 0x00,
                0x04, 0x30
        };
        private static final byte SHA512_AID[] = {
                0x30, 0x51,
                0x30, 0x0d,
                0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                        0x03,
                0x05, 0x00,
                0x04, 0x40
        };
}
