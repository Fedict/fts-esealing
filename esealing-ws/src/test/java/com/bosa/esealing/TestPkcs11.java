package com.bosa.esealing;

import java.io.IOException;
import java.math.BigInteger;
import java.io.ByteArrayInputStream;
import java.security.Signature;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Properties;

import com.bosa.esealing.service.GenDer;
import jakarta.xml.bind.DatatypeConverter;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.objects.GenericTemplate;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.Storage;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.ECPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

public class TestPkcs11 {
	public static void main(String[] args) throws Exception {
		String tokenLabel = null;
		String tokenPin = null;
		if (args.length == 0)
			;
		else if (args.length == 2 && !args[0].startsWith("-")) {
			tokenLabel = args[0];
			tokenPin = args[1];
		}
		else {
			System.out.println("Run without any parameters, or specify a token label + the user PIN of that token");
			System.out.println("    E.g. 'selor test123'");
			return;
		}

		String libLocation = System.getenv("SOFTHSM2_CONF");
		if (libLocation == null) throw new IOException("SOFTHSM2_CONF not set !!!!");
		libLocation = libLocation.replaceFirst("etc\\\\.*$", "") +
				(System.getProperty("os.name").toLowerCase().contains("win") ? "lib\\softhsm2-x64.dll" : "lib\\libsofthsm2.so");
		System.out.println("Loading PKCS11 Library from system property 'SOFTHSM2_CONF' : " + libLocation);
		Module module = Module.getInstance(libLocation);

		module.initialize(null);

		Slot[] slots = module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
		if (null == slots) {
			System.out.println("getSlotList() returned null, exiting");
			return;
		}
		System.out.println("Slots:");
		Token token = null;
		for (Slot slot : slots) {
			Token t = slot.getToken();
			TokenInfo ti = t.getTokenInfo();
			String label = ti.getLabel().trim();
			System.out.println(" - Slot ID = " + slot.getSlotID() + ", label = " + label);

			if (null != tokenLabel && tokenLabel.equals(label))
				token = t;
		}

		if (null == token) {
			if (null != tokenLabel)
				System.out.println("\nNo token with label '" + tokenLabel + "' found, exiting");
			return;
		}
		String label = token.getTokenInfo().getLabel().trim();

		System.out.println("\nMechanisms for token " + label + ":");
		for (Mechanism mech : token.getMechanismList())
			System.out.print(" " + mech.getName());

		boolean rwSession = true;
		Session session = token.openSession(Token.SessionType.SERIAL_SESSION, rwSession, null, null);
		System.out.println("\n\nOpened session to token " + label);

		session.login(Session.UserType.USER, tokenPin.toCharArray());
		System.out.println("\nLogged into token " + label);

		GenericTemplate templ = new GenericTemplate();
		session.findObjectsInit(templ);
		PKCS11Object[] objects = session.findObjects(50);
		session.findObjectsFinal();
		if (null == objects) {
			System.out.println("\nfindObjects() returned null, exiting");
			return;
		}

		System.out.println("\nObjects in token " + label + ":");
		for (PKCS11Object obj : objects) {
			dumpObj(obj);
		}

		for (PKCS11Object obj : objects) {
			if (obj instanceof PrivateKey) {
				PrivateKey privKey = (PrivateKey) obj;
				
				ByteArrayAttribute keyId = privKey.getId();
				X509Certificate cert = null;
				for (PKCS11Object o : objects) {
					if (o instanceof X509PublicKeyCertificate) {
						X509PublicKeyCertificate c = (X509PublicKeyCertificate) o;
						if (keyId.equals(c.getId())) {
							cert = (X509Certificate) CertificateFactory.getInstance("X509")
								.generateCertificate(new ByteArrayInputStream(c.getValue().getByteArrayValue()));
							break;
						}
					}
				}

				makeSig(session, privKey, cert);
//break;
			}
		}
	}

	private static void makeSig(Session session, PrivateKey privKey, X509Certificate cert) throws Exception {

		/*
		byte[] hashAID = SHA384_AID;
		int sha2HashLen = 384;

		byte[] hashAID = SHA256_AID;
		int sha2HashLen = 256;
		*/
		byte[] hashAID = SHA512_AID;
		int sha2HashLen = 512;

		byte[] tbs = new byte[100];
		(new java.util.Random()).nextBytes(tbs);

		String hashAlg = "SHA-" + sha2HashLen;
		byte[] hashVal = MessageDigest.getInstance(hashAlg).digest(tbs);

		if (privKey instanceof ECPrivateKey) {
			System.out.println("\nTrying to sign with private EC key '" + privKey.getLabel() + "'");
			ECPrivateKey ecKey = (ECPrivateKey) privKey;

			session.signInit(new Mechanism(PKCS11Constants.CKM_ECDSA), ecKey);
			byte[] sigVal = session.sign(hashVal);

			byte[] r = new byte[sigVal.length / 2];
			byte[] s = new byte[sigVal.length / 2];
			System.arraycopy(sigVal, 0, r, 0, r.length);
			System.arraycopy(sigVal, r.length, s, 0, s.length);
			sigVal = GenDer.make(0x30, new byte[][] {
				GenDer.make(0x02, (new BigInteger(1, r)).toByteArray()),
				GenDer.make(0x02, (new BigInteger(1, s)).toByteArray()),
			});

			checkSig(tbs, sigVal, "SHA" + sha2HashLen + "WithECDSA", cert);
		}
		else if (privKey instanceof RSAPrivateKey) {
			System.out.println("\nTrying to sign with private RSA key '" + privKey.getLabel() + "'");
			RSAPrivateKey rsaKey = (RSAPrivateKey) privKey;

			byte[] sigInp = new byte[hashAID.length + hashVal.length];
			System.arraycopy(hashAID, 0, sigInp, 0, hashAID.length);
			System.arraycopy(hashVal, 0, sigInp, hashAID.length, hashVal.length);

			session.signInit(new Mechanism(PKCS11Constants.CKM_RSA_PKCS), rsaKey);
			byte[] sigVal = session.sign(sigInp);

			checkSig(tbs, sigVal, "SHA" + sha2HashLen + "WithRSA", cert);
		}
		else
			System.out.println("\nCan't sign with key '" + privKey.getLabel() + ": not supported");
	}

	private static void checkSig(byte[] tbs, byte[] sigVal, String algo, X509Certificate cert) {
		try {
			System.out.println("  sig: " + DatatypeConverter.printHexBinary(sigVal));

			Signature signat = Signature.getInstance(algo);
			signat.initVerify(cert.getPublicKey());
			signat.update(tbs);
			boolean sigOK = signat.verify(sigVal);
			System.out.println("  verification " + (sigOK ? "succeeded" : "failed"));
		}
		catch(Exception e) {
			System.out.println("  verification failed: " + e.toString());
		}
	}

	private static void dumpObj(PKCS11Object obj) throws Exception {
		String id = null;
		if (obj instanceof Key)
			id = DatatypeConverter.printHexBinary(((Key) obj).getId().getByteArrayValue());
		if (obj instanceof X509PublicKeyCertificate)
			id = DatatypeConverter.printHexBinary(((X509PublicKeyCertificate) obj).getId().getByteArrayValue());
		
		System.out.println(" - " + obj.getClass() + ", ID: " + id + ", label: " + ((Storage) obj).getLabel());
	}

        private static final byte  SHA1_AID[] = {
                0x30, 0x21,
                0x30, 0x09,
                0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
                0x05, 0x00,
                0x04, 0x14
        };
        private static final byte  SHA256_AID[] = {
                0x30, 0x31,
                0x30, 0x0d,
                0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                        0x01,
                0x05, 0x00,
                0x04, 0x20
        };
        private static final byte  SHA384_AID[] = {
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
