package com.zetes.projects.bosa.esealing.model;

/**
 * See https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf 2019-03, par 8.6.1
 * See https://forge.etsi.org/rep/esi/x19_432_sign_creation_protocol/raw/v1.1.1/19432-openapi.yaml - certificate-information-retrieval-request
 */
public class InfoRequest {

    private String requestID;
    private String credentialID;
    private String lang;
    private String returnCertificates;
    private Boolean certInfo;
    private Boolean authInfo;
    private String profile;

    public InfoRequest() {
    }

    /**
     * @param requestID           not relevant (only in case of asynchronous communication) - see par 7.3
     * @param credentialID        unique reference to the signing key (see also ListResponse) - see par 7.8
     * @param lang                requested response language, e.g. "en", "nl", "fr", "de" - see par 7.9
     * @param returnCertificates  which certificates should be returned, allowed values: are "none", "single" (= default), "chain" - see par 7.10
     * @param certInfo            true if info about the end entity certs should be included as printable strings, false (= default) otherwise - see par 7.10
     * @param authInfo            true if info on the authorization mechanisms should be included, false (= default) otherwise - see par 7.10
     * @param profile             not relvant, set to null - see par 7.15
     */
    public InfoRequest(String requestID, String credentialID, String lang, String returnCertificates, Boolean certInfo, Boolean authInfo, String profile) {
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

    public String getReturnCertificates() {
        return returnCertificates;
    }

    public void setReturnCertificates(String returnCertificates) {
        this.returnCertificates = returnCertificates;
    }

    public Boolean getCertInfo() {
        return certInfo;
    }

    public void setCertInfo(Boolean certInfo) {
        this.certInfo = certInfo;
    }

    public Boolean getAuthInfo() {
        return authInfo;
    }

    public void setAuthInfo(Boolean authInfo) {
        this.authInfo = authInfo;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

}
