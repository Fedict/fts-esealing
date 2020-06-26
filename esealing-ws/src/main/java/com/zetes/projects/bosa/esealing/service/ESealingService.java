package com.zetes.projects.bosa.esealing.service;

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

        // voorbeeldje exception
        if (authorization == null) {
            throw new ESealException(401, "Authorization null", "Authorization should not be null");
        }

        return new ListResponse("error", "error_description", "policy", "responseID");
    }

    public InfoResponse getCredentialsInfo(String authorization, InfoRequest infoRequest) throws ESealException {
        LOG.info("Getting credentials info...");

        Cert cert = new Cert("status", new String[]{"certificates"}, "validFrom", "validTo", "issuerDN", "serialNumber", "subjectDN");
        Key key = new Key("status", new String[]{"algo"}, 1, 1);
        return new InfoResponse(cert, key, true, "error", "error_description", "authMode", "SCAL");
    }

    public SignResponse signHash(String authorization, SignRequest signRequest) throws ESealException {
        LOG.info("Signing hash...");

        Cert cert = new Cert("status", new String[]{"certificates"}, "validFrom", "validTo", "issuerDN", "serialNumber", "subjectDN");
        Key key = new Key("status", new String[]{"algo"}, 1, 1);
        return new SignResponse(cert, key, true, "error", "error_description", "policy", "responseID", "signaturePolicyID", new String[]{"signaturePolicyLocations"}, new String[]{"signatures"});
    }

}
