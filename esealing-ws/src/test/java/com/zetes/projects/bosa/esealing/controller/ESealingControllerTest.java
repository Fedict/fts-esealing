package com.zetes.projects.bosa.esealing.controller;

import com.zetes.projects.bosa.esealing.ESealingTestBase;
import com.zetes.projects.bosa.esealing.model.*;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

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
    public void testAuthorizationNOK() throws Exception {
        // given
        ListRequest listRequest = new ListRequest();

        // when
        ResponseEntity<ListResponse> response = this.restTemplate.postForEntity(LOCALHOST + port + CREDLIST_ENDPOINT, listRequest, ListResponse.class);

        // then
        assertEquals(BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void testCredentialsList() throws Exception {
        // given
        ListRequest listRequest = new ListRequest();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic YWJjOmRlZg==");
        HttpEntity<ListRequest> request = new HttpEntity<>(listRequest, headers);

        // when
        ListResponse response = this.restTemplate.postForObject(LOCALHOST + port + CREDLIST_ENDPOINT, request, ListResponse.class);

        // then
        assertNotNull(response);
    }

    @Test
    public void testCredentialsInfo() throws Exception {
        // given
        InfoRequest infoRequest = new InfoRequest();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic YWJjOmRlZg==");
        HttpEntity<InfoRequest> request = new HttpEntity<>(infoRequest, headers);

        // when
        InfoResponse response = this.restTemplate.postForObject(LOCALHOST + port + CREDINFO_ENDPOINT, request, InfoResponse.class);

        // then
        assertNotNull(response);
    }

    @Test
    public void testSignHash() throws Exception {
        // given
        SignRequest signRequest = new SignRequest();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic YWJjOmRlZg==");
        HttpEntity<SignRequest> request = new HttpEntity<>(signRequest, headers);

        // when
        SignResponse response = this.restTemplate.postForObject(LOCALHOST + port + SIGNHASH_ENDPOINT, request, SignResponse.class);

        // then
        assertNotNull(response);
    }

}
