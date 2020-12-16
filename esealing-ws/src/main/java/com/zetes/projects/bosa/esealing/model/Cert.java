package com.zetes.projects.bosa.esealing.model;

/**
 * See https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf 2019-03, par 7.22
 * See https://forge.etsi.org/rep/esi/x19_432_sign_creation_protocol/raw/v1.1.1/19432-openapi.yaml - cert
 */
 public class Cert {

    private String status;
    private String[] certificates;
    private String validFrom;
    private String validTo;
    private String issuerDN;
    private String serialNumber;
    private String subjectDN;

    public Cert() {
    }

    public Cert(String status, String[] certificates, String validFrom, String validTo, String issuerDN, String serialNumber, String subjectDN) {
        this.status = status;
        this.certificates = certificates;
        this.validFrom = validFrom;
        this.validTo = validTo;
        this.issuerDN = issuerDN;
        this.serialNumber = serialNumber;
        this.subjectDN = subjectDN;
    }

    /** Returns "valid" or "expired" or "evoked" or "suspended" */
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    /** Base64-encoded certificate chain, starting with the signing cert */
    public String[] getCertificates() {
        return certificates;
    }

    public void setCertificates(String[] certificates) {
        this.certificates = certificates;
    }

    /** Cert begin validity date in 'YYYYMMDDHHMMSSZ' GeneralizedTime format, e.g. "20200122150100+0100"*/
    public String getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(String validFrom) {
        this.validFrom = validFrom;
    }

    /** Cert end validity datein 'YYYYMMDDHHMMSSZ' GeneralizedTime format, e.g. "20320108150100+0100" */
    public String getValidTo() {
        return validTo;
    }

    public void setValidTo(String validTo) {
        this.validTo = validTo;
    }

    /** Issuer DN, e.g. "C=BE,O=fgov,OU=BOSA,CN=Test CA" */
     public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

   /** Serialnumber in hex */
   public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    /** Subject DN, e.g. "C=BE,O=fgov,OU=BOSA,CN=Test" */
    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

}
