package com.zetes.projects.bosa.esealing.model;

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

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String[] getCertificates() {
        return certificates;
    }

    public void setCertificates(String[] certificates) {
        this.certificates = certificates;
    }

    public String getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(String validFrom) {
        this.validFrom = validFrom;
    }

    public String getValidTo() {
        return validTo;
    }

    public void setValidTo(String validTo) {
        this.validTo = validTo;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

}
