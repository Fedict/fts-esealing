package com.zetes.projects.bosa.esealing;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("local")
public class ESealingTestBase {

    public static final String LOCALHOST = "http://localhost:";

    @LocalServerPort
    public int port;

    @Autowired
    public TestRestTemplate restTemplate;

    @Test
    void contextLoads() {
    }

}
