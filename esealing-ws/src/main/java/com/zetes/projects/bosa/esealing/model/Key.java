package com.zetes.projects.bosa.esealing.model;

public class Key {

    private String status;
    private String[] algo;
    private Integer len;
    private Integer curve;

    public Key() {
    }

    public Key(String status, String[] algo, Integer len, Integer curve) {
        this.status = status;
        this.algo = algo;
        this.len = len;
        this.curve = curve;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String[] getAlgo() {
        return algo;
    }

    public void setAlgo(String[] algo) {
        this.algo = algo;
    }

    public Integer getLen() {
        return len;
    }

    public void setLen(Integer len) {
        this.len = len;
    }

    public Integer getCurve() {
        return curve;
    }

    public void setCurve(Integer curve) {
        this.curve = curve;
    }
}
