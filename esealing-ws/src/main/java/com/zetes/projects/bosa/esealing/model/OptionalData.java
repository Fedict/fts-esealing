package com.zetes.projects.bosa.esealing.model;

public class OptionalData {

    private Boolean returnSigningCertificateInfo;
    private Boolean returnSupportMultiSignatureInfo;
    private Boolean returnServicePolicyInfo;
    private Boolean returnSignatureCreationPolicyInfo;
    private Boolean returnCredentialAuthorizationModeInfo;
    private Boolean returnSoleControlAssuranceLevelInfo;

    public OptionalData() {
    }

    public OptionalData(Boolean returnSigningCertificateInfo, Boolean returnSupportMultiSignatureInfo, Boolean returnServicePolicyInfo, Boolean returnSignatureCreationPolicyInfo, Boolean returnCredentialAuthorizationModeInfo, Boolean returnSoleControlAssuranceLevelInfo) {
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
