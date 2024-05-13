package com.bosa.esealing.dssmodel;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Date;

/** See https://git-fsf.services.belgium.be/eidas/sign-validation
 *  /signandvalidation-ws/src/main/java/com/bosa/signandvalidation/model/DataToSignDTO.java */
@Getter
@NoArgsConstructor
public class DataToSignDTO {

	public DigestAlgorithm digestAlgorithm;
	public byte[] digest;

	@JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss.SSSZ")
	private Date signingDate;
}
