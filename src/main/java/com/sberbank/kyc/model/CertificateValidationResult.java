package com.sberbank.kyc.model;

import java.security.cert.TrustAnchor;

public class CertificateValidationResult {
    private boolean valid;
    private ValidationResult failureReason;
    private String errorMessage;
    private TrustAnchor trustAnchor;
    
    public void setValid(boolean v) { this.valid = v; }
    public boolean isValid() { return valid; }
    public void setFailureReason(ValidationResult reason) { this.failureReason = reason; }
    public ValidationResult getFailureReason() { return failureReason; }
    public void setErrorMessage(String msg) { this.errorMessage = msg; }
    public String getErrorMessage() { return errorMessage; }
    public void setTrustAnchor(TrustAnchor anchor) { this.trustAnchor = anchor; }
}
