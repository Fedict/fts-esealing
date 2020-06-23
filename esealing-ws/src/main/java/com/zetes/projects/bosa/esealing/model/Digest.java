package com.zetes.projects.bosa.esealing.model;

public class Digest {

    private String[] hashes;
    private String hashAlgorithmOID;

    public Digest() {
    }

    public Digest(String[] hashes, String hashAlgorithmOID) {
        this.hashes = hashes;
        this.hashAlgorithmOID = hashAlgorithmOID;
    }

    public String[] getHashes() {
        return hashes;
    }

    public void setHashes(String[] hashes) {
        this.hashes = hashes;
    }

    public String getHashAlgorithmOID() {
        return hashAlgorithmOID;
    }

    public void setHashAlgorithmOID(String hashAlgorithmOID) {
        this.hashAlgorithmOID = hashAlgorithmOID;
    }

}
