package com.bosa.esealing.service;

import java.util.HashMap;
import java.security.cert.X509Certificate;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.Session;

/** Contains info (avialable keys and certs) about an HSM token. */
class HsmTokenInfo {
	Token token;
	Session session;
	HashMap<String, HsmKeyInfo> keys;
	X509Certificate[] certs;

	HsmTokenInfo(Token token, Session session, HashMap<String, HsmKeyInfo> keys, X509Certificate[] certs) {
		this.session = session;
		this.token = token;
		this.keys = keys;
		this.certs = certs;
	}
}
