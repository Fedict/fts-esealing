package com.zetes.projects.bosa.esealing.controller;

import com.zetes.projects.bosa.esealing.model.*;
import com.zetes.projects.bosa.esealing.service.ESealingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@RequestMapping
public class ESealingController {

    @Autowired
    private ESealingService ESealingService;

    @GetMapping(value = "/ping", produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @PostMapping(value = "/credentials/list", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ListResponse credentialsList(@RequestBody ListRequest listRequest) {
        return ESealingService.getCredentialsList(listRequest);
    }

    @PostMapping(value = "/credentials/info", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public InfoResponse credentialsInfo(@RequestBody InfoRequest infoRequest) {
        return ESealingService.getCredentialsInfo(infoRequest);
    }

    @PostMapping(value = "/signatures/signHash", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public SignResponse signHash(@RequestBody SignRequest signRequest) {
        return ESealingService.signHash(signRequest);
    }

}
