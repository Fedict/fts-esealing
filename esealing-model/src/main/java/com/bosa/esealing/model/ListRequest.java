package com.bosa.esealing.model;

/**
 * See https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf 2019-03, par 8.5.1
 * See https://forge.etsi.org/rep/esi/x19_432_sign_creation_protocol/raw/v1.1.1/19432-openapi.yaml - signing-certificates-list-request
 */
public class ListRequest {

    private String requestID;
    private String lang;
    private String certificates;
    private Boolean certInfo;
    private Boolean authInfo;
    private String profile;
    private String signerIdentity;

    public ListRequest() {
    }

    /**
     * @param requestID       not relevant (only in case of asynchronous communication) - see par 7.3
     * @param lang            requested response language, e.g. "en", "nl", "fr", "de" - see par 7.9
     * @param certificates    which certificates should be returned, allowed values: are "none", "single" (= default), "chain" - see par 7.10
     * @param certInfo        true if info about the end entity certs should be included as printable strings, false (= default) otherwise - see par 7.10
     * @param authInfo        true if info on the authorization mechanisms should be included, false (= default) otherwise - see par 7.10
     * @param profile         not relvant, set to null - see par 7.15
     * @param signerIdentity  unique ID to identify the signer - see par 7.17
     */
     public ListRequest(String requestID, String lang, String certificates, Boolean certInfo, Boolean authInfo, String profile, String signerIdentity) {
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

    public String getCertificates() {
        return certificates;
    }

    public void setCertificates(String certificates) {
        this.certificates = certificates;
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

    public String getSignerIdentity() {
        return signerIdentity;
    }

    public void setSignerIdentity(String signerIdentity) {
        this.signerIdentity = signerIdentity;
    }

}
