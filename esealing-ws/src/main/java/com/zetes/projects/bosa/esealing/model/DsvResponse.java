package com.zetes.projects.bosa.esealing.model;

/**
 * See https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf 2019-03, par 8.3.2
 * See https://forge.etsi.org/rep/esi/x19_432_sign_creation_protocol/raw/v1.1.1/19432-openapi.yaml - DSV-creation-request
 */
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

    public DsvResponse(Cert cert, Key key, Boolean multisign, String error, String error_description, String policy,
		String responseID, String signaturePolicyID, String[] signaturePolicyLocations, String[] signatures) {
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

    /** Signing certificate info - see par 7.22.2 */
    public Cert getCert() {
        return cert;
    }

    public void setCert(Cert cert) {
        this.cert = cert;
    }

   /** Signing key info - see par 7.22.2 */
    public Key getKey() {
        return key;
    }

    public void setKey(Key key) {
        this.key = key;
    }

    /** If multiple signatures can be created with a signle authorization request - see par 7.22.2 */
    public Boolean getMultisign() {
        return multisign;
    }

    public void setMultisign(Boolean multisign) {
        this.multisign = multisign;
    }

    /** Error code - see par 7.24.2 */
    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    /** Error description - see par 7.24.2 */
    public String getError_description() {
        return error_description;
    }

    public void setError_description(String error_description) {
        this.error_description = error_description;
    }

    /** Name of the service policy that was used - see par 7.25.2 */
    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

    /** Unique identification of this response */
    public String getResponseID() {
        return responseID;
    }

    public void setResponseID(String responseID) {
        this.responseID = responseID;
    }

    /** see par 7.2 */
    public String getSignaturePolicyID() {
        return signaturePolicyID;
    }

    public void setSignaturePolicyID(String signaturePolicyID) {
        this.signaturePolicyID = signaturePolicyID;
    }

    /** URIs referering to the signature creation policy - see par 7.27.2 */
    public String[] getSignaturePolicyLocations() {
        return signaturePolicyLocations;
    }

    public void setSignaturePolicyLocations(String[] signaturePolicyLocations) {
        this.signaturePolicyLocations = signaturePolicyLocations;
    }

    public String[] getSignatures() {
        return signatures;
    }

    /** Signature(s) - see par 7.29.2 */
    public void setSignatures(String[] signatures) {
        this.signatures = signatures;
    }

}
