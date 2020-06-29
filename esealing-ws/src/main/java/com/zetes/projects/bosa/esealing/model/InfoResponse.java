package com.zetes.projects.bosa.esealing.model;

/**
 * See https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf 2019-03, par 8.6.2
 * See https://forge.etsi.org/rep/esi/x19_432_sign_creation_protocol/raw/v1.1.1/19432-openapi.yaml - certificate-information-retrieval-response
 */
public class InfoResponse {

    private Cert cert;
    private Key key;
    private Boolean multisign;
    private String error;
    private String error_description;
    private String authMode;
    private String SCAL;

    public InfoResponse() {
    }

    public InfoResponse(String error, String error_description) {
        this.error = error;
        this.error_description = error_description;
    }

    public InfoResponse(Cert cert, Key key, Boolean multisign, String error, String error_description, String authMode, String SCAL) {
        this.cert = cert;
        this.key = key;
        this.multisign = multisign;
        this.error = error;
        this.error_description = error_description;
        this.authMode = authMode;
        this.SCAL = SCAL;
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

    /** Credential authorization mode: "implicit" or "explicit" or "authorizationCode" or "identificationToken" - see par 7.28.2 */
    public String getAuthMode() {
        return authMode;
    }

    public void setAuthMode(String authMode) {
        this.authMode = authMode;
    }

    /** SCAL level required: "SCAL1" or "SCAL2" - see par 7.30.2 */
    public String getSCAL() {
        return SCAL;
    }

    public void setSCAL(String SCAL) {
        this.SCAL = SCAL;
    }
}
