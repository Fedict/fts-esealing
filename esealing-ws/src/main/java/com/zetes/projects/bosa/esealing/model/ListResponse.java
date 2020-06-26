package com.zetes.projects.bosa.esealing.model;

public class ListResponse {

    private String error;
    private String error_description;
    private String policy;
    private String responseID;

    public ListResponse() {
    }

    public ListResponse(String error, String error_description) {
        this.error = error;
        this.error_description = error_description;
    }

    public ListResponse(String error, String error_description, String policy, String responseID) {
        this.error = error;
        this.error_description = error_description;
        this.policy = policy;
        this.responseID = responseID;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getError_description() {
        return error_description;
    }

    public void setError_description(String error_description) {
        this.error_description = error_description;
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

    public String getResponseID() {
        return responseID;
    }

    public void setResponseID(String responseID) {
        this.responseID = responseID;
    }

}
