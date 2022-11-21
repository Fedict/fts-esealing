package com.bosa.esealing.controller;

import com.bosa.esealing.ESealingTestBase;
import com.bosa.esealing.model.*;
import com.bosa.esealing.service.SadUtil;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.HttpHeaders.WWW_AUTHENTICATE;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

public class ESealingControllerTest extends ESealingTestBase {

    public static final String CREDLIST_ENDPOINT = "/credentials/list";
    public static final String CREDINFO_ENDPOINT = "/credentials/info";
    public static final String SIGNHASH_ENDPOINT = "/signatures/signHash";

    @Test
    public void pingShouldReturnPong() throws Exception {
        // when
        String result = this.restTemplate.getForObject(LOCALHOST + port + "/ping", String.class);

        // then
        assertEquals("pong", result);
    }

    @Test
    public void testAuthorizationExample() throws Exception {
        // given
        ListRequest listRequest = new ListRequest();

        // when
        ResponseEntity<ListResponse> response = this.restTemplate.postForEntity(LOCALHOST + port + CREDLIST_ENDPOINT, listRequest, ListResponse.class);

        // then
        assertEquals(UNAUTHORIZED, response.getStatusCode());
        assertEquals("Basic realm=\"User Visible Realm\"", response.getHeaders().get(WWW_AUTHENTICATE).get(0));
        assertEquals("Authorization null", response.getBody().getError());
        assertEquals("Authorization should not be null", response.getBody().getError_description());
    }

    @Test
    public void testCredentialsList() throws Exception {
        // given
        String requestId = "sdklzelfqlfsmqzpmeifsl";
	Boolean certInfo = false;
	Boolean authInfo = false;
	String profile = "http://uri.etsi.org/19432/v1.1.1/certificateslistprotocol#";
	String signerIdentity = null;
	String lang = "en";
	String certs = "none";
	ListRequest listRequest = new ListRequest(requestId, lang, certs, certInfo, authInfo, profile, signerIdentity);
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("sealing", "123456");
        HttpEntity<ListRequest> request = new HttpEntity<>(listRequest, headers);

        // when
        ListResponse response = this.restTemplate.postForObject(LOCALHOST + port + CREDLIST_ENDPOINT, request, ListResponse.class);

        // then
        assertNotNull(response);
        assertEquals("OK", response.getError());
    }

    @Test
    public void testCredentialsInfo() throws Exception {
        // given
	String requestId = "837620383892799873630";
	Boolean certInfo = true;
	Boolean authInfo = true;
	String profile = "http://uri.etsi.org/19432/v1.1.1/credentialinfoprotocol#";
	String credentialID = "interm_sealing";
	String lang = "en";
	String certs = "chain";
	InfoRequest infoRequest = new InfoRequest(requestId, credentialID, lang, certs, certInfo, authInfo, profile);
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("sealing", "123456");
        HttpEntity<InfoRequest> request = new HttpEntity<>(infoRequest, headers);

        // when
        InfoResponse response = this.restTemplate.postForObject(LOCALHOST + port + CREDINFO_ENDPOINT, request, InfoResponse.class);

        // then
        assertNotNull(response);
        assertEquals("OK", response.getError());
    }

    @Test
    public void testSignHash() throws Exception {
        // given

	String operationMode = "S";
	String requestId = "1159445535673610071799690907";
	String lang = "en";
	String credentialID = "final_sealing";
	OptionalData optionalData = new OptionalData(true, true, true, true, true, true);
	Integer validity_period = null;
	Integer numSignatures = new Integer(1);
	String policy = null;
	String signaturePolicyID = null;
	String response_uri = null;
	String signAlgoParams = null;
	String signOID = "1.2.840.10045.4.3.3";  // ecdsa-with-SHA384
	String digestOID = "2.16.840.1.101.3.4.2.2"; // SHA384
	String[] digestsB64 = new String[] {
		"5nyRwCYYZO7KXu8RpLgOAyb9SA+pNcvrFcyYQ1VohJEpPlra9psyUm1WqIJ826a0",
		"TF7cQNdjOBTH5v4RoaX7hf5A7/GpmfP51bFi3EfgxFj92stT1h6rnI88OJTaIEhM",
	};
	Digest documentDigests = new Digest(digestsB64, digestOID);
	String SAD = SadUtil.makeSAD(documentDigests);
	DsvRequest dsvRequest = new DsvRequest(operationMode, requestId, SAD, optionalData, validity_period,
		credentialID, lang, numSignatures, policy, signaturePolicyID, signOID, signAlgoParams, response_uri, documentDigests);

        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("sealing", "123456");
        HttpEntity<DsvRequest> request = new HttpEntity<>(dsvRequest, headers);

        // when
        DsvResponse response = this.restTemplate.postForObject(LOCALHOST + port + SIGNHASH_ENDPOINT, request, DsvResponse.class);

        // then
        assertNotNull(response);
        assertEquals("OK", response.getError());
    }
}
