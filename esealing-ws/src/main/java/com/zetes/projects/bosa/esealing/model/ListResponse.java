package com.zetes.projects.bosa.esealing.model;

/**
 * See https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf, par 8.5.2
 * See https://forge.etsi.org/rep/esi/x19_432_sign_creation_protocol/raw/v1.1.1/19432-openapi.yaml - signing-certificates-list-response
 */
public class ListResponse {

    private String error;
    private String error_description;
    private String[] credentialIDs;
    private String[] certificates;

    public ListResponse() {
    }

    public ListResponse(String error, String error_description, String[] credentialIDs, String[] certificates) {
        this.error = error;
        this.error_description = error_description;
        this.credentialIDs = credentialIDs;
        this.certificates = certificates;
    }

    public ListResponse(String error, String error_description) {
        this.error = error;
        this.error_description = error_description;
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

    /** Returns the credential IDs for this signer */
    public String[] getCredentialIDs() {
        return credentialIDs;
    }

    public void setCredentialIDs(String[] credentialIDs) {
        this.credentialIDs = credentialIDs;
    }

    /** Returns the PEM encoded certificate(s) chain(s) for this signer.
     * Depending on the 'certificate' value in the 'ListRequest', this can be empty ("none"),
     * the signing certificate ("single") or the certificate chain with the end user cert first ("chain")
     */
    public String[] getCertificates() {
        return certificates;
    }

    public void setCertificates(String[] certificates) {
        this.certificates = certificates;
    }

}
