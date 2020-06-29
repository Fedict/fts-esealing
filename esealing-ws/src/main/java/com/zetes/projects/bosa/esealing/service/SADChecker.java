package com.zetes.projects.bosa.esealing.service;

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
}
