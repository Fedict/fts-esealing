package com.zetes.projects.bosa.esealing.model;

public class ListRequest {

    private String requestID;
    private String lang;
    private String[] certificates;
    private Boolean certInfo;
    private String authInfo;
    private String profile;
    private String signerIdentity;

    public ListRequest() {
    }

    public ListRequest(String requestID, String lang, String[] certificates, Boolean certInfo, String authInfo, String profile, String signerIdentity) {
        this.requestID = requestID;
        this.lang = lang;
        this.certificates = certificates;
        this.certInfo = certInfo;
        this.authInfo = authInfo;
        this.profile = profile;
        this.signerIdentity = signerIdentity;
    }

    public String getRequestID() {
        return requestID;
    }

    public void setRequestID(String requestID) {
        this.requestID = requestID;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String[] getCertificates() {
        return certificates;
    }

    public void setCertificates(String[] certificates) {
        this.certificates = certificates;
    }

    public Boolean getCertInfo() {
        return certInfo;
    }

    public void setCertInfo(Boolean certInfo) {
        this.certInfo = certInfo;
    }

    public String getAuthInfo() {
        return authInfo;
    }

    public void setAuthInfo(String authInfo) {
        this.authInfo = authInfo;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getSignerIdentity() {
        return signerIdentity;
    }

    public void setSignerIdentity(String signerIdentity) {
        this.signerIdentity = signerIdentity;
    }

}
