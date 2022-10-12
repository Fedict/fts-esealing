package com.bosa.esealing.dssmodel;

/** See https://github.com/esig/dss.git
 *  dss-sources/dss-common-remote-dto/src/main/java/eu/europa/esig/dss/ws/dto/RemoteCertificate.java */
public class RemoteCertificate {

	public byte[] encodedCertificate;

	public RemoteCertificate(byte[] encodedCertificate) {
		this.encodedCertificate = encodedCertificate;
	}
}
