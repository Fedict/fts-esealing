package com.zetes.projects.bosa.esealing.service;

import com.zetes.projects.bosa.esealing.exception.ESealException;
import com.zetes.projects.bosa.esealing.model.DsvRequest;

class SADChecker {

	private static SADChecker sadChecker = null;

	public static SADChecker getInstance() {
		if (null == sadChecker)
			sadChecker = new SADChecker();
		return sadChecker;
	}

	private SADChecker() {
	}

	public String getAuthMode() {
		return "identificationToken";
	}

	public void checkDsv(DsvRequest dsvRequest) throws ESealException {
		// TODO
	}
}
