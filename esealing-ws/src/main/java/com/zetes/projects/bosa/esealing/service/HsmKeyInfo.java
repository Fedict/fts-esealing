package com.zetes.projects.bosa.esealing.service;

import java.security.cert.X509Certificate;
import com.zetes.projects.bosa.esealing.model.Cert;
import com.zetes.projects.bosa.esealing.model.Key;

/** Contains info about a key (and corresponding cert chain) in an HSM token */
class HsmKeyInfo {
	byte[] id;
	X509Certificate[] chain;

	HsmKeyInfo(byte[] id, X509Certificate[] chain) {
		this.id = id;
		this.chain = chain;
	}
}
