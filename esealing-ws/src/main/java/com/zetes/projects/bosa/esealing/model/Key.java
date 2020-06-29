package com.zetes.projects.bosa.esealing.model;

/**
 * See https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf 2019-03, par 7.22
 * See https://forge.etsi.org/rep/esi/x19_432_sign_creation_protocol/raw/v1.1.1/19432-openapi.yaml - key
 */
public class Key {

    private String status;
    private String[] algo;
    private Integer len;
    private String curve;

    public Key() {
    }

    public Key(String status, String[] algo, Integer len, String curve) {
        this.status = status;
        this.algo = algo;
        this.len = len;
        this.curve = curve;
    }

    /** "enabled" (key can be used) or "disabled" (key can't be used) */
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    /** OIDs of the supported algorithms, e.g. "1.2.840.113549.1.1.11" for 'sha256WithRSAEncryption' */
    public String[] getAlgo() {
        return algo;
    }

    public void setAlgo(String[] algo) {
        this.algo = algo;
    }

    /** Bit length of the key */
    public Integer getLen() {
        return len;
    }

    public void setLen(Integer len) {
        this.len = len;
    }

    /** OID of the Ellpic Curve, in case of EC keys, e.g. "1.3.132.0.34" for 'secp384r1' */
    public String getCurve() {
        return curve;
    }

    public void setCurve(String curve) {
        this.curve = curve;
    }
}
