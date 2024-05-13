package com.bosa.esealing.dssmodel;

/** See https://github.com/esig/dss.git
 *  dss-sources/dss-common-remote-dto/src/main/java/eu/europa/esig/dss/ws/dto/RemoteDocument.java */
public class RemoteDocument {

	public byte[] bytes;
	/* Allows to send only the digest of the document */
	public DigestAlgorithm digestAlgorithm;
	public String name = "RemoteDocument";

	public RemoteDocument() {
	}

	public RemoteDocument(byte[] bytes) {
		this.bytes = bytes;
	}
}
