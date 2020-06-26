package com.zetes.projects.bosa.esealing.model;

public class DsvResponse {

    private Cert cert;
    private Key key;
    private Boolean multisign;
    private String error;
    private String error_description;
    private String policy;
    private String responseID;
    private String signaturePolicyID;
    private String[] signaturePolicyLocations;
    private String[] signatures;

    public DsvResponse() {
    }

    public DsvResponse(String error, String error_description) {
        this.error = error;
        this.error_description = error_description;
    }

    public DsvResponse(Cert cert, Key key, Boolean multisign, String error, String error_description, String policy, String responseID, String signaturePolicyID, String[] signaturePolicyLocations, String[] signatures) {
        this.cert = cert;
        this.key = key;
        this.multisign = multisign;
        this.error = error;
        this.error_description = error_description;
        this.policy = policy;
        this.responseID = responseID;
        this.signaturePolicyID = signaturePolicyID;
        this.signaturePolicyLocations = signaturePolicyLocations;
        this.signatures = signatures;
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

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

    public String getResponseID() {
        return responseID;
    }

    public void setResponseID(String responseID) {
        this.responseID = responseID;
    }

    public String getSignaturePolicyID() {
        return signaturePolicyID;
    }

    public void setSignaturePolicyID(String signaturePolicyID) {
        this.signaturePolicyID = signaturePolicyID;
    }

    public String[] getSignaturePolicyLocations() {
        return signaturePolicyLocations;
    }

    public void setSignaturePolicyLocations(String[] signaturePolicyLocations) {
        this.signaturePolicyLocations = signaturePolicyLocations;
    }

    public String[] getSignatures() {
        return signatures;
    }

    public void setSignatures(String[] signatures) {
        this.signatures = signatures;
    }

}
