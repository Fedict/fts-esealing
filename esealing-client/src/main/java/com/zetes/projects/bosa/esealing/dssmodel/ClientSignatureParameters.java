package com.zetes.projects.bosa.esealing.dssmodel;

import java.util.List;
import java.util.ArrayList;
import java.util.Date;
import java.security.cert.Certificate;

/** See https://git-fsf.services.belgium.be/eidas/sign-validation
 *  signingconfigurator/src/main/java/com/zetes/projects/bosa/signingconfigurator/model/ClientSignatureParameters.java */
public class ClientSignatureParameters {

	public RemoteCertificate signingCertificate;
	public List<RemoteCertificate> certificateChain = new ArrayList<RemoteCertificate>();

	public List<RemoteDocument> detachedContents;

	public Date signingDate;

	public List<String> claimedSignerRoles;

	public List<String> signerLocationPostalAddress = new ArrayList<String>();
	public String signerLocationPostalCode;
	public String signerLocationLocality;
	public String signerLocationStateOrProvince;
	public String signerLocationCountry;
	public String signerLocationStreet;

	/** @param certChain  the certificate chain, with the signing certificate first */
	public ClientSignatureParameters(byte[][] certChain) {
		this.signingCertificate = new RemoteCertificate(certChain[0]);
		this.certificateChain = new ArrayList<RemoteCertificate>(certChain.length);
		// Cert chain to be sent to the DSS service may (must?) contain the signing cert itself
		for (int i = 1; i < certChain.length; i++)
			this.certificateChain.add(new RemoteCertificate(certChain[i]));
		this.signingDate = new Date();
	}
}

