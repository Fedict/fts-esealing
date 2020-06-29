package com.zetes.projects.bosa.esealing.controller;

import com.zetes.projects.bosa.esealing.ESealingTestBase;
import com.zetes.projects.bosa.esealing.model.*;
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
        ListRequest listRequest = new ListRequest();
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("selor", "test123");
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
        headers.setBasicAuth("selor", "test123");
        HttpEntity<InfoRequest> request = new HttpEntity<>(infoRequest, headers);

        // when
        InfoResponse response = this.restTemplate.postForObject(LOCALHOST + port + CREDINFO_ENDPOINT, request, InfoResponse.class);

        // then
        assertNotNull(response);
    }

    @Test
    public void testSignHash() throws Exception {
        // given
        DsvRequest dsvRequest = new DsvRequest();
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("selor", "test123");
        HttpEntity<DsvRequest> request = new HttpEntity<>(dsvRequest, headers);

        // when
        DsvResponse response = this.restTemplate.postForObject(LOCALHOST + port + SIGNHASH_ENDPOINT, request, DsvResponse.class);

        // then
        assertNotNull(response);
    }

}
