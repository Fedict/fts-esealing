package com.zetes.projects.bosa.esealing.model;

public class InfoRequest {

    private String requestID;
    private String credentialID;
    private String lang;
    private String[] returnCertificates;
    private Boolean certInfo;
    private String authInfo;
    private String profile;

    public InfoRequest() {
    }

    public InfoRequest(String requestID, String credentialID, String lang, String[] returnCertificates, Boolean certInfo, String authInfo, String profile) {
        this.requestID = requestID;
        this.credentialID = credentialID;
        this.lang = lang;
        this.returnCertificates = returnCertificates;
        this.certInfo = certInfo;
        this.authInfo = authInfo;
        this.profile = profile;
    }

    public String getRequestID() {
        return requestID;
    }

    public void setRequestID(String requestID) {
        this.requestID = requestID;
    }

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String[] getReturnCertificates() {
        return returnCertificates;
    }

    public void setReturnCertificates(String[] returnCertificates) {
        this.returnCertificates = returnCertificates;
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

}
