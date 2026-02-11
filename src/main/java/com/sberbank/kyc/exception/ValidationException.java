package com.sberbank.kyc.exception;

public class ValidationException extends Exception {
    private static final long serialVersionUID = 1L;
    private final String errorCode;
    
    public ValidationException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
    
    public String getErrorCode() {
        return errorCode;
    }
}
