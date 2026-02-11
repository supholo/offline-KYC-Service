package com.sberbank.kyc.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Response model for QR KYC Validation
 * 
 * @author Sberbank India - Enterprise Architecture
 * @version 1.0
 */
public class QRKYCValidationResponse {
    
    // Request tracking
    private String requestId;
    private Instant validationTimestamp;
    private long processingTimeMs;
    
    // Overall result
    private boolean success;
    private ValidationResult result;
    private String successMessage;
    private String errorMessage;
    
    // QR Format info
    private String qrVersion;
    private String qrFormat;  // SECURE_QR_V2, SECURE_QR_V1, NON_SECURE_QR
    
    // Validation flags
    private boolean signatureValid;
    private boolean certificateChainValid;
    private boolean shareCodeValid;
    private boolean mobileVerified;
    private String signatureAlgorithm;
    
    // Certificate info
    private CertificateInfo certificateInfo;
    
    // Extracted KYC Data
    private KYCData kycData;
    
    // Warnings (non-fatal issues)
    private List<String> warnings = new ArrayList<>();
    
    // Constructors
    public QRKYCValidationResponse() {
        this.warnings = new ArrayList<>();
    }
    
    // Getters and Setters
    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }
    
    public Instant getValidationTimestamp() { return validationTimestamp; }
    public void setValidationTimestamp(Instant validationTimestamp) { this.validationTimestamp = validationTimestamp; }
    
    public long getProcessingTimeMs() { return processingTimeMs; }
    public void setProcessingTimeMs(long processingTimeMs) { this.processingTimeMs = processingTimeMs; }
    
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    
    public ValidationResult getResult() { return result; }
    public void setResult(ValidationResult result) { this.result = result; }
    
    public String getSuccessMessage() { return successMessage; }
    public void setSuccessMessage(String successMessage) { this.successMessage = successMessage; }
    
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    
    public String getQrVersion() { return qrVersion; }
    public void setQrVersion(String qrVersion) { this.qrVersion = qrVersion; }
    
    public String getQrFormat() { return qrFormat; }
    public void setQrFormat(String qrFormat) { this.qrFormat = qrFormat; }
    
    public boolean isSignatureValid() { return signatureValid; }
    public void setSignatureValid(boolean signatureValid) { this.signatureValid = signatureValid; }
    
    public boolean isCertificateChainValid() { return certificateChainValid; }
    public void setCertificateChainValid(boolean certificateChainValid) { this.certificateChainValid = certificateChainValid; }
    
    public boolean isShareCodeValid() { return shareCodeValid; }
    public void setShareCodeValid(boolean shareCodeValid) { this.shareCodeValid = shareCodeValid; }
    
    public boolean isMobileVerified() { return mobileVerified; }
    public void setMobileVerified(boolean mobileVerified) { this.mobileVerified = mobileVerified; }
    
    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public void setSignatureAlgorithm(String signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }
    
    public CertificateInfo getCertificateInfo() { return certificateInfo; }
    public void setCertificateInfo(CertificateInfo certificateInfo) { this.certificateInfo = certificateInfo; }
    
    public KYCData getKycData() { return kycData; }
    public void setKycData(KYCData kycData) { this.kycData = kycData; }
    
    public List<String> getWarnings() { return warnings; }
    public void setWarnings(List<String> warnings) { this.warnings = warnings; }
    
    public void addWarning(String warning) {
        if (this.warnings == null) {
            this.warnings = new ArrayList<>();
        }
        this.warnings.add(warning);
    }
}