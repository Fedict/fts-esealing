package com.bosa.esealing.service;

import com.bosa.esealing.exception.ESealException;
import com.bosa.esealing.model.*;

import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class ESealingService {

    private static final Logger LOG = LoggerFactory.getLogger(ESealingService.class);

    public ListResponse getCredentialsList(String authorization, ListRequest listRequest) throws ESealException {
        LOG.info("Getting credentials list...");

        String[] auth = checkAuthorization(authorization);

        return Hsm.getHsm().getCredentialsList(auth[0], auth[1].toCharArray(), listRequest.getCertificates());
    }

    public InfoResponse getCredentialsInfo(String authorization, InfoRequest infoRequest) throws ESealException {
        LOG.info("Getting credentials info...");

        String[] auth = checkAuthorization(authorization);

        return Hsm.getHsm().getCredentialsInfo(auth[0], auth[1].toCharArray(), infoRequest.getCredentialID(),
                infoRequest.getReturnCertificates(), infoRequest.getCertInfo(), infoRequest.getAuthInfo());
    }

    public DsvResponse signHash(String authorization, DsvRequest dsvRequest) throws ESealException {
        LOG.info("Signing hash...");

        String[] auth = checkAuthorization(authorization);

        SADChecker.getInstance().checkDsv(auth[0], auth[1].toCharArray(), dsvRequest);

        return Hsm.getHsm().signHash(auth[0], auth[1].toCharArray(), dsvRequest.getCredentialID(),
                dsvRequest.getOptionalData(), dsvRequest.getSignAlgo(), dsvRequest.getDocumentDigests());
    }

	private String[] checkAuthorization(String authorization) throws ESealException {
		if (authorization == null) 
			throw new ESealException(401, "Authorization null", "Authorization should not be null");

		int idx = authorization.indexOf("Basic ") + "Basic ".length();
		authorization = authorization.substring(idx);

		authorization = new String (Base64.decodeBase64(authorization));

		String[] parts = authorization.split(":"); // parts[0] = username, parts[1] = passwd
		if (parts.length != 2)
			throw new ESealException(401, "Bad Authorization", "Authorization format is wrong");

		return parts;
	}
}
