package com.zetes.projects.bosa.esealing.client;

import com.zetes.projects.bosa.esealing.dssmodel.*;

/** Little helper class for returning several objects from the Client.getDataToSign() method */
public class DataToSignInfo {
	public RemoteDocument toSignDocument;
	public ClientSignatureParameters clientSignatureParameters;
	public String profileName;
	public DataToSignDTO dataToSignDTO;

	public DataToSignInfo(RemoteDocument toSignDocument, ClientSignatureParameters clientSignatureParameters,
			String profileName, DataToSignDTO dataToSignDTO) {
		this.toSignDocument = toSignDocument;
		this.clientSignatureParameters = clientSignatureParameters;
		this.profileName = profileName;
		this.dataToSignDTO = dataToSignDTO;
	}
}

