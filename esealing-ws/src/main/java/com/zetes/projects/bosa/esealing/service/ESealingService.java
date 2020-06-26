package com.zetes.projects.bosa.esealing.service;

import javax.xml.bind.DatatypeConverter;

import com.zetes.projects.bosa.esealing.exception.ESealException;
import com.zetes.projects.bosa.esealing.model.*;

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

        Cert cert = new Cert("status", new String[]{"certificates"}, "validFrom", "validTo", "issuerDN", "serialNumber", "subjectDN");
        Key key = new Key("status", new String[]{"algo"}, 1, 1);
        return new InfoResponse(cert, key, true, "error", "error_description", "authMode", "SCAL");
    }

    public DsvResponse signHash(String authorization, DsvRequest dsvRequest) throws ESealException {
        LOG.info("Signing hash...");

        Cert cert = new Cert("status", new String[]{"certificates"}, "validFrom", "validTo", "issuerDN", "serialNumber", "subjectDN");
        Key key = new Key("status", new String[]{"algo"}, 1, 1);
        return new DsvResponse(cert, key, true, "error", "error_description", "policy", "responseID", "signaturePolicyID", new String[]{"signaturePolicyLocations"}, new String[]{"signatures"});
    }

	private String[] checkAuthorization(String authorization) throws ESealException {
		if (authorization == null) 
			throw new ESealException(401, "Authorization null", "Authorization should not be null");

		int idx = authorization.indexOf("Basic ") + "Basic ".length();
		authorization = authorization.substring(idx);

		authorization = new String (DatatypeConverter.parseBase64Binary(authorization));

		String[] parts = authorization.split(":"); // parts[0] = username, parts[1] = passwd
		if (parts.length != 2)
			throw new ESealException(401, "Bad Authorization", "Authorization format is wrong");

		return parts;
	}
}
