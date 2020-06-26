package com.zetes.projects.bosa.esealing.controller;

import com.zetes.projects.bosa.esealing.exception.ESealException;
import com.zetes.projects.bosa.esealing.model.*;
import com.zetes.projects.bosa.esealing.service.ESealingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.WWW_AUTHENTICATE;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
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
    public ResponseEntity<ListResponse> credentialsList(HttpEntity<ListRequest> request) {
        try {
            String authorization = getAuthorizationHeader(request.getHeaders());
            ListResponse listResponse = ESealingService.getCredentialsList(authorization, request.getBody());

            return new ResponseEntity<>(listResponse, HttpStatus.OK);
        } catch (ESealException e) {
            ListResponse listResponse = new ListResponse(e.getError(), e.getErrorDescription());
            HttpStatus status = HttpStatus.valueOf(e.getHttpStatus());

            if (status != UNAUTHORIZED) {
                return new ResponseEntity<>(listResponse, status);
            } else {
                HttpHeaders headers = getWwwAuthenticateHeader();
                return new ResponseEntity<>(listResponse, headers, status);
            }
        }
    }

    @PostMapping(value = "/credentials/info", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<InfoResponse> credentialsInfo(HttpEntity<InfoRequest> request) {
        try {
            String authorization = getAuthorizationHeader(request.getHeaders());
            InfoResponse infoResponse = ESealingService.getCredentialsInfo(authorization, request.getBody());

            return new ResponseEntity<>(infoResponse, HttpStatus.OK);
        } catch (ESealException e) {
            InfoResponse infoResponse = new InfoResponse(e.getError(), e.getErrorDescription());
            HttpStatus status = HttpStatus.valueOf(e.getHttpStatus());

            if (status != UNAUTHORIZED) {
                return new ResponseEntity<>(infoResponse, status);
            } else {
                HttpHeaders headers = getWwwAuthenticateHeader();
                return new ResponseEntity<>(infoResponse, headers, status);
            }
        }
    }

    @PostMapping(value = "/signatures/signHash", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<DsvResponse> signHash(HttpEntity<DsvRequest> request) {
        try {
            String authorization = getAuthorizationHeader(request.getHeaders());
            DsvResponse dsvResponse = ESealingService.signHash(authorization, request.getBody());

            return new ResponseEntity<>(dsvResponse, HttpStatus.OK);
        } catch (ESealException e) {
            DsvResponse dsvResponse = new DsvResponse(e.getError(), e.getErrorDescription());
            HttpStatus status = HttpStatus.valueOf(e.getHttpStatus());

            if (status != UNAUTHORIZED) {
                return new ResponseEntity<>(dsvResponse, status);
            } else {
                HttpHeaders headers = getWwwAuthenticateHeader();
                return new ResponseEntity<>(dsvResponse, headers, status);
            }
        }
    }

    private String getAuthorizationHeader(HttpHeaders headers) {
        if (headers.containsKey(AUTHORIZATION)) {
            return headers.get(AUTHORIZATION).get(0);
        } else {
            return null;
        }
    }

    private HttpHeaders getWwwAuthenticateHeader() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(WWW_AUTHENTICATE, "Basic realm=\"User Visible Realm\"");
        return headers;
    }

}
