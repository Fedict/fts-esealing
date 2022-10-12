package com.bosa.esealing.model;

/**
 * See https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf 2019-03, par 7.5
 * See https://forge.etsi.org/rep/esi/x19_432_sign_creation_protocol/raw/v1.1.1/19432-openapi.yaml - optionalData
 */
public class OptionalData {

    private Boolean returnSigningCertificateInfo;
    private Boolean returnSupportMultiSignatureInfo;
    private Boolean returnServicePolicyInfo;
    private Boolean returnSignatureCreationPolicyInfo;
    private Boolean returnCredentialAuthorizationModeInfo;
    private Boolean returnSoleControlAssuranceLevelInfo;

    public OptionalData() {
    }

    /**
     * @param returnSigningCertificateInfo          if true then certificate and key info is returned
     * @param returnSupportMultiSignatureInfo       if true then the response contains info whether multiple signatures are allowed with a single authentication
     * @param returnServicePolicyInfo               if true then the service policy info is returned
     * @param returnSignatureCreationPolicyInfo     if true then signature creation policy info is returned
     * @param returnCredentialAuthorizationModeInfo if true then the authorization mode for this credential is returned
     * @param returnSoleControlAssuranceLevelInfo   if true then sole control assurance level is returned
     */
    public OptionalData(Boolean returnSigningCertificateInfo, Boolean returnSupportMultiSignatureInfo, Boolean returnServicePolicyInfo,
		Boolean returnSignatureCreationPolicyInfo, Boolean returnCredentialAuthorizationModeInfo, Boolean returnSoleControlAssuranceLevelInfo) {
        this.returnSigningCertificateInfo = returnSigningCertificateInfo;
        this.returnSupportMultiSignatureInfo = returnSupportMultiSignatureInfo;
        this.returnServicePolicyInfo = returnServicePolicyInfo;
        this.returnSignatureCreationPolicyInfo = returnSignatureCreationPolicyInfo;
        this.returnCredentialAuthorizationModeInfo = returnCredentialAuthorizationModeInfo;
        this.returnSoleControlAssuranceLevelInfo = returnSoleControlAssuranceLevelInfo;
    }

    public Boolean getReturnSigningCertificateInfo() {
        return returnSigningCertificateInfo;
    }

    public void setReturnSigningCertificateInfo(Boolean returnSigningCertificateInfo) {
        this.returnSigningCertificateInfo = returnSigningCertificateInfo;
    }

    public Boolean getReturnSupportMultiSignatureInfo() {
        return returnSupportMultiSignatureInfo;
    }

    public void setReturnSupportMultiSignatureInfo(Boolean returnSupportMultiSignatureInfo) {
        this.returnSupportMultiSignatureInfo = returnSupportMultiSignatureInfo;
    }

    public Boolean getReturnServicePolicyInfo() {
        return returnServicePolicyInfo;
    }

    public void setReturnServicePolicyInfo(Boolean returnServicePolicyInfo) {
        this.returnServicePolicyInfo = returnServicePolicyInfo;
    }

    public Boolean getReturnSignatureCreationPolicyInfo() {
        return returnSignatureCreationPolicyInfo;
    }

    public void setReturnSignatureCreationPolicyInfo(Boolean returnSignatureCreationPolicyInfo) {
        this.returnSignatureCreationPolicyInfo = returnSignatureCreationPolicyInfo;
    }

    public Boolean getReturnCredentialAuthorizationModeInfo() {
        return returnCredentialAuthorizationModeInfo;
    }

    public void setReturnCredentialAuthorizationModeInfo(Boolean returnCredentialAuthorizationModeInfo) {
        this.returnCredentialAuthorizationModeInfo = returnCredentialAuthorizationModeInfo;
    }

    public Boolean getReturnSoleControlAssuranceLevelInfo() {
        return returnSoleControlAssuranceLevelInfo;
    }

    public void setReturnSoleControlAssuranceLevelInfo(Boolean returnSoleControlAssuranceLevelInfo) {
        this.returnSoleControlAssuranceLevelInfo = returnSoleControlAssuranceLevelInfo;
    }

}
