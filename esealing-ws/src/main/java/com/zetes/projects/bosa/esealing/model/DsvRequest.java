package com.zetes.projects.bosa.esealing.model;

/**
 * See https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf 2019-03, par 8.3.1
 * See https://forge.etsi.org/rep/esi/x19_432_sign_creation_protocol/raw/v1.1.1/19432-openapi.yaml - DSV-creation-request
 */
public class DsvRequest {

    private String operationMode;
    private String requestID;
    private String SAD;
    private OptionalData optionalData;
    private Integer validity_period;
    private String credentialID;
    private String lang;
    private Integer numSignatures;
    private String policy;
    private String signaturePolicyID;
    private String signAlgo;
    private String signAlgoParams;
    private String response_uri;
    private Digest documentDigests;

    public DsvRequest() {
    }

    /**
     * @param operationMode     requested mode: "A" (asynchronous) or "S" (synchronous) - see par 7.2
     * @param requestID         not relevant here (only in case of asynchronous communication) - see par 7.3
     * @param SAD               information (e.g. a SAML, id_token, ..) that authorizes the signature creation - see par 7.4
     * @param optionalData      optional data to be returned (certificate info, policy info, ...) - see par 7.5
     * @param validity_period   validity period in millieconds, only relevant for asynchronous requests  - see par 7.6
     * @param credentialID      unique reference to the signing key (see also ListResponse) - see par 7.8
     * @param lang              requested response language, e.g. "en", "nl", "fr", "de" - see par 7.9
     * @param numSignatures     set to 1 - see par 7.11.1
     * @param policy            identifies a particular service policy - see par 7.12
     * @param signaturePolicyID identfies a particular signature creation policy if the 'signAlgo' is not specified - see par 7.13
     * @param signAlgo          signature algorithm OID, e.g. "1.2.840.113549.1.1.11" for 'sha256WithRSA' - see par 7.13
     * @param signAlgoParams    signature algorithm parameters (e.g. for RSA-PSS) - see  par 7.13
     * @param response_uri      not relevant here (only in case of asynchronous communication) - see par 7.18
     * @param documentDigests   hash value(s) to be signed - see par 7.19
     */
    public DsvRequest(String operationMode, String requestID, String SAD, OptionalData optionalData, Integer validity_period, String credentialID, String lang, Integer numSignatures, String policy, String signaturePolicyID, String signAlgo, String signAlgoParams, String response_uri, Digest documentDigests) {
        this.operationMode = operationMode;
        this.requestID = requestID;
        this.SAD = SAD;
        this.optionalData = optionalData;
        this.validity_period = validity_period;
        this.credentialID = credentialID;
        this.lang = lang;
        this.numSignatures = numSignatures;
        this.policy = policy;
        this.signaturePolicyID = signaturePolicyID;
        this.signAlgo = signAlgo;
        this.signAlgoParams = signAlgoParams;
        this.response_uri = response_uri;
        this.documentDigests = documentDigests;
    }

    public String getOperationMode() {
        return operationMode;
    }

    public void setOperationMode(String operationMode) {
        this.operationMode = operationMode;
    }

    public String getRequestID() {
        return requestID;
    }

    public void setRequestID(String requestID) {
        this.requestID = requestID;
    }

    public String getSAD() {
        return SAD;
    }

    public void setSAD(String SAD) {
        this.SAD = SAD;
    }

    public OptionalData getOptionalData() {
        return optionalData;
    }

    public void setOptionalData(OptionalData optionalData) {
        this.optionalData = optionalData;
    }

    public Integer getValidity_period() {
        return validity_period;
    }

    public void setValidity_period(Integer validity_period) {
        this.validity_period = validity_period;
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

    public Integer getNumSignatures() {
        return numSignatures;
    }

    public void setNumSignatures(Integer numSignatures) {
        this.numSignatures = numSignatures;
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

    public String getSignaturePolicyID() {
        return signaturePolicyID;
    }

    public void setSignaturePolicyID(String signaturePolicyID) {
        this.signaturePolicyID = signaturePolicyID;
    }

    public String getSignAlgo() {
        return signAlgo;
    }

    public void setSignAlgo(String signAlgo) {
        this.signAlgo = signAlgo;
    }

    public String getSignAlgoParams() {
        return signAlgoParams;
    }

    public void setSignAlgoParams(String signAlgoParams) {
        this.signAlgoParams = signAlgoParams;
    }

    public String getResponse_uri() {
        return response_uri;
    }

    public void setResponse_uri(String response_uri) {
        this.response_uri = response_uri;
    }

    public Digest getDocumentDigests() {
        return documentDigests;
    }

    public void setDocumentDigests(Digest documentDigests) {
        this.documentDigests = documentDigests;
    }

}
