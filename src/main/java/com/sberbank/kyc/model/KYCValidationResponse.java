package com.sberbank.kyc.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Response object containing complete KYC validation results.
 * 
 * Includes:
 * - Overall validation result status
 * - Individual validation flags (signature, certificate, share code, integrity)
 * - Extracted KYC data
 * - Certificate information
 * - Error/Success messages
 * - Warnings list
 * 
 * @author Sberbank India - Enterprise Architecture
 * @version 2.0
 */
public class KYCValidationResponse {
    
    // Validation result
    private ValidationResult result;
    private String errorMessage;
    private String successMessage;
    private Instant validationTimestamp;
    
    // Individual validation flags
    private boolean signatureValid;
    private boolean certificateChainValid;
    private boolean shareCodeValid;
    private boolean dataIntegrityValid;
    
    // Certificate and KYC data
    private CertificateInfo certificateInfo;
    private KYCData kycData;
    
    // Warnings list
    private List<Warning> warnings;
    
    // Constructor
    public KYCValidationResponse() {
        this.warnings = new ArrayList<>();
        this.validationTimestamp = Instant.now();
    }
    
    // ==================== RESULT ====================
    
    public ValidationResult getResult() {
        return result;
    }
    
    public void setResult(ValidationResult result) {
        this.result = result;
    }
    
    // ==================== ERROR MESSAGE ====================
    
    public String getErrorMessage() {
        return errorMessage;
    }
    
    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
    
    // ==================== SUCCESS MESSAGE ====================
    
    public String getSuccessMessage() {
        return successMessage;
    }
    
    public void setSuccessMessage(String successMessage) {
        this.successMessage = successMessage;
    }
    
    // ==================== VALIDATION TIMESTAMP ====================
    
    public Instant getValidationTimestamp() {
        return validationTimestamp;
    }
    
    public void setValidationTimestamp(Instant validationTimestamp) {
        this.validationTimestamp = validationTimestamp;
    }
    
    // ==================== SIGNATURE VALID ====================
    
    public boolean isSignatureValid() {
        return signatureValid;
    }
    
    public void setSignatureValid(boolean signatureValid) {
        this.signatureValid = signatureValid;
    }
    
    // ==================== CERTIFICATE CHAIN VALID ====================
    
    public boolean isCertificateChainValid() {
        return certificateChainValid;
    }
    
    public void setCertificateChainValid(boolean certificateChainValid) {
        this.certificateChainValid = certificateChainValid;
    }
    
    // ==================== SHARE CODE VALID ====================
    
    public boolean isShareCodeValid() {
        return shareCodeValid;
    }
    
    public void setShareCodeValid(boolean shareCodeValid) {
        this.shareCodeValid = shareCodeValid;
    }
    
    // ==================== DATA INTEGRITY VALID ====================
    
    public boolean isDataIntegrityValid() {
        return dataIntegrityValid;
    }
    
    public void setDataIntegrityValid(boolean dataIntegrityValid) {
        this.dataIntegrityValid = dataIntegrityValid;
    }
    
    // ==================== CERTIFICATE INFO ====================
    
    public CertificateInfo getCertificateInfo() {
        return certificateInfo;
    }
    
    public void setCertificateInfo(CertificateInfo certificateInfo) {
        this.certificateInfo = certificateInfo;
    }
    
    // ==================== KYC DATA ====================
    
    public KYCData getKycData() {
        return kycData;
    }
    
    public void setKycData(KYCData kycData) {
        this.kycData = kycData;
    }
    
    // ==================== WARNINGS ====================
    
    public List<Warning> getWarnings() {
        return warnings;
    }
    
    public void setWarnings(List<Warning> warnings) {
        this.warnings = warnings;
    }
    
    /**
     * Add a warning to the response
     * @param code Warning code
     * @param message Warning message
     */
    public void addWarning(String code, String message) {
        if (this.warnings == null) {
            this.warnings = new ArrayList<>();
        }
        this.warnings.add(new Warning(code, message));
    }
    
    /**
     * Check if there are any warnings
     * @return true if warnings exist
     */
    public boolean hasWarnings() {
        return warnings != null && !warnings.isEmpty();
    }
    
    // ==================== UTILITY METHODS ====================
    
    /**
     * Check if overall validation was successful
     * @return true if result is VALID
     */
    public boolean isValid() {
        return result == ValidationResult.VALID;
    }
    
    /**
     * Check if all individual validations passed
     * @return true if all flags are true
     */
    public boolean isAllValidationsPassed() {
        return signatureValid && certificateChainValid && shareCodeValid && dataIntegrityValid;
    }
    
    @Override
    public String toString() {
        return "KYCValidationResponse{" +
                "result=" + result +
                ", signatureValid=" + signatureValid +
                ", certificateChainValid=" + certificateChainValid +
                ", shareCodeValid=" + shareCodeValid +
                ", dataIntegrityValid=" + dataIntegrityValid +
                ", hasKycData=" + (kycData != null) +
                ", warningsCount=" + (warnings != null ? warnings.size() : 0) +
                '}';
    }
    
    // ==================== INNER CLASS: WARNING ====================
    
    /**
     * Inner class to represent validation warnings
     */
    public static class Warning {
        private String code;
        private String message;
        
        public Warning() {}
        
        public Warning(String code, String message) {
            this.code = code;
            this.message = message;
        }
        
        public String getCode() {
            return code;
        }
        
        public void setCode(String code) {
            this.code = code;
        }
        
        public String getMessage() {
            return message;
        }
        
        public void setMessage(String message) {
            this.message = message;
        }
        
        @Override
        public String toString() {
            return "Warning{code='" + code + "', message='" + message + "'}";
        }
    }
}
