package com.zetes.projects.bosa.esealing.exception;

public class ESealException extends Exception {

    int httpStatus;
    String error;
    String errorDescription;

    public ESealException(int httpStatus, String error, String errorDescription) {
        this.httpStatus = httpStatus;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

}
