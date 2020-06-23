package com.zetes.projects.bosa.esealing.controller;

import com.zetes.projects.bosa.esealing.ESealingTestBase;
import com.zetes.projects.bosa.esealing.model.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    public void testCredentialsList() throws Exception {
        // given
        ListRequest listRequest = new ListRequest();

        // when
        ListResponse response = this.restTemplate.postForObject(LOCALHOST + port + CREDLIST_ENDPOINT, listRequest, ListResponse.class);

        // then
        assertNotNull(response);
    }

    @Test
    public void testCredentialsInfo() throws Exception {
        // given
        InfoRequest infoRequest = new InfoRequest();

        // when
        InfoResponse response = this.restTemplate.postForObject(LOCALHOST + port + CREDINFO_ENDPOINT, infoRequest, InfoResponse.class);

        // then
        assertNotNull(response);
    }

    @Test
    public void testSignHash() throws Exception {
        // given
        SignRequest signRequest = new SignRequest();

        // when
        SignResponse response = this.restTemplate.postForObject(LOCALHOST + port + SIGNHASH_ENDPOINT, signRequest, SignResponse.class);

        // then
        assertNotNull(response);
    }

}
