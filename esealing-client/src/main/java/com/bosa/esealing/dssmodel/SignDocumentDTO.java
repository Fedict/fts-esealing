package com.bosa.esealing.dssmodel;

/** See https://git-fsf.services.belgium.be/eidas/sign-validation
 *  signandvalidation-ws/src/main/java/com/bosa/signandvalidation/model/SignDocumentDTO.java */
 public class SignDocumentDTO {

	public RemoteDocument toSignDocument;
	public String signingProfileId;
	public ClientSignatureParameters clientSignatureParameters;
	public byte[] signatureValue;

	public SignDocumentDTO(RemoteDocument toSignDocument, String signingProfileId,
			ClientSignatureParameters clientSignatureParameters, byte[] signatureValue) {
		this.toSignDocument = toSignDocument;
		this.signingProfileId = signingProfileId;
		this.clientSignatureParameters = clientSignatureParameters;
		this.signatureValue = signatureValue;
	}
}
