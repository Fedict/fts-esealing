package com.bosa.esealing.dssmodel;

/** See https://git-fsf.services.belgium.be/eidas/sign-validation
 *  signandvalidation-ws/src/main/java/com/bosa/signandvalidation/model/GetDataToSignDTO.java */
public class GetDataToSignDTO {

	public ClientSignatureParameters clientSignatureParameters;
	public String signingProfileId;
	public RemoteDocument toSignDocument;

	public GetDataToSignDTO(RemoteDocument toSignDocument, String signingProfileId,
			ClientSignatureParameters clientSignatureParameters) {
		this.toSignDocument = toSignDocument;
		this.signingProfileId = signingProfileId;
		this.clientSignatureParameters = clientSignatureParameters;
	}
}
