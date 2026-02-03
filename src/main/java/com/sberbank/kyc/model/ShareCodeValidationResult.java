package com.sberbank.kyc.model;

public class ShareCodeValidationResult {
    private boolean valid;
    private String message;
    private String errorMessage;
    private boolean mobileHashPresent;
    private boolean emailHashPresent;
    
    public void setValid(boolean v) { this.valid = v; }
    public boolean isValid() { return valid; }

    public void setMessage(String msg) { this.message = msg; }
    public String getMessage() { return message; }

    public void setErrorMessage(String msg) { this.errorMessage = msg; }
    public String getErrorMessage() { return errorMessage; }

    public void setMobileHashPresent(boolean v) { this.mobileHashPresent = v; }
    public boolean isMobileHashPresent() { return mobileHashPresent; }

    public void setEmailHashPresent(boolean v) { this.emailHashPresent = v; }
    public boolean isEmailHashPresent() { return emailHashPresent; }
}
