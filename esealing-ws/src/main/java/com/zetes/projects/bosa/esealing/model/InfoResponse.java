package com.zetes.projects.bosa.esealing.model;

public class InfoResponse {

    private Cert cert;
    private Key key;
    private Boolean multisign;
    private String error;
    private String error_description;
    private String authMode;
    private String SCAL;

    public InfoResponse() {
    }

    public InfoResponse(String error, String error_description) {
        this.error = error;
        this.error_description = error_description;
    }

    public InfoResponse(Cert cert, Key key, Boolean multisign, String error, String error_description, String authMode, String SCAL) {
        this.cert = cert;
        this.key = key;
        this.multisign = multisign;
        this.error = error;
        this.error_description = error_description;
        this.authMode = authMode;
        this.SCAL = SCAL;
    }

    public Cert getCert() {
        return cert;
    }

    public void setCert(Cert cert) {
        this.cert = cert;
    }

    public Key getKey() {
        return key;
    }

    public void setKey(Key key) {
        this.key = key;
    }

    public Boolean getMultisign() {
        return multisign;
    }

    public void setMultisign(Boolean multisign) {
        this.multisign = multisign;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getError_description() {
        return error_description;
    }

    public void setError_description(String error_description) {
        this.error_description = error_description;
    }

    public String getAuthMode() {
        return authMode;
    }

    public void setAuthMode(String authMode) {
        this.authMode = authMode;
    }

    public String getSCAL() {
        return SCAL;
    }

    public void setSCAL(String SCAL) {
        this.SCAL = SCAL;
    }
}
