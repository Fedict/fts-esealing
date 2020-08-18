package com.zetes.projects.bosa.esealing.dssmodel;

/** See https://git-fsf.services.belgium.be/eidas/sign-validation
 *  /signandvalidation-ws/src/main/java/com/zetes/projects/bosa/signandvalidation/model/DataToSignDTO.java */
public class DataToSignDTO {

	public DigestAlgorithm digestAlgorithm;
	public byte[] digest;
}
