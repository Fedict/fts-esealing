package com.zetes.projects.bosa.esealing.model;

/**
 * See https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf 2019-03, par 8.5.1
 * See https://forge.etsi.org/rep/esi/x19_432_sign_creation_protocol/raw/v1.1.1/19432-openapi.yaml - signing-certificates-list-request
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
    private Attribute[] signed_props;
    private String signature_format;
    private String conformance_level;
    private String response_uri;
    private String[] documents;
    private Digest[] documentDigests;

    public DsvRequest() {
    }

    /**
     * @param operationMode
     */
    public DsvRequest(String operationMode, String requestID, String SAD, OptionalData optionalData, Integer validity_period, String credentialID, String lang, Integer numSignatures, String policy, String signaturePolicyID, String signAlgo, String signAlgoParams, Attribute[] signed_props, String signature_format, String conformance_level, String response_uri, String[] documents, Digest[] documentDigests) {
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
        this.signed_props = signed_props;
        this.signature_format = signature_format;
        this.conformance_level = conformance_level;
        this.response_uri = response_uri;
        this.documents = documents;
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

    public Attribute[] getSigned_props() {
        return signed_props;
    }

    public void setSigned_props(Attribute[] signed_props) {
        this.signed_props = signed_props;
    }

    public String getSignature_format() {
        return signature_format;
    }

    public void setSignature_format(String signature_format) {
        this.signature_format = signature_format;
    }

    public String getConformance_level() {
        return conformance_level;
    }

    public void setConformance_level(String conformance_level) {
        this.conformance_level = conformance_level;
    }

    public String getResponse_uri() {
        return response_uri;
    }

    public void setResponse_uri(String response_uri) {
        this.response_uri = response_uri;
    }

    public String[] getDocuments() {
        return documents;
    }

    public void setDocuments(String[] documents) {
        this.documents = documents;
    }

    public Digest[] getDocumentDigests() {
        return documentDigests;
    }

    public void setDocumentDigests(Digest[] documentDigests) {
        this.documentDigests = documentDigests;
    }

}
