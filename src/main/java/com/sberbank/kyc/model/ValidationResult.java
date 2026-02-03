package com.sberbank.kyc.model;

/**
 * Enum representing all possible KYC validation outcomes.
 * 
 * Used across validator, service, and controller layers for
 * consistent validation status reporting.
 * 
 * @author Sberbank India - Enterprise Architecture
 * @version 2.0
 */
public enum ValidationResult {
    
    /** Validation completed successfully - all checks passed */
    VALID("KYC_VALID", "Offline KYC XML validated successfully"),
    
    /** XML digital signature verification failed */
    INVALID_SIGNATURE("KYC_INVALID_SIGNATURE", "XML digital signature validation failed"),
    
    /** Signing certificate has expired */
    EXPIRED_CERTIFICATE("KYC_CERT_EXPIRED", "Signing certificate has expired"),
    
    /** Signing certificate has been revoked */
    REVOKED_CERTIFICATE("KYC_CERT_REVOKED", "Signing certificate has been revoked"),
    
    /** Certificate chain does not lead to trusted UIDAI Root CA */
    INVALID_CERTIFICATE_CHAIN("KYC_INVALID_CERT_CHAIN", "Certificate chain validation failed"),
    
    /** XML file could not be parsed */
    XML_PARSE_ERROR("KYC_XML_PARSE_ERROR", "Failed to parse XML document"),
    
    /** Share code validation failed */
    SHARE_CODE_MISMATCH("KYC_SHARE_CODE_MISMATCH", "Share code validation failed"),
    
    /** Data integrity check failed */
    DATA_INTEGRITY_FAILED("KYC_INTEGRITY_FAILED", "XML data integrity verification failed"),
    
    /** File size exceeds maximum allowed */
    FILE_TOO_LARGE("KYC_FILE_TOO_LARGE", "File size exceeds maximum allowed limit"),
    
    /** Invalid file type uploaded */
    INVALID_FILE_TYPE("KYC_INVALID_FILE_TYPE", "Invalid file type. Expected XML file"),
    
    /** Empty or missing file */
    EMPTY_FILE("KYC_EMPTY_FILE", "XML file is required"),
    
    MOBILE_VERIFICATION_FAILED("KYC_MOBILE_MISMATCH", "Mobile number verification failed"),
    
    /** Unknown or unexpected error */
    UNKNOWN_ERROR("KYC_UNKNOWN_ERROR", "An unexpected error occurred during validation");
    
    private final String code;
    private final String defaultMessage;
    
    ValidationResult(String code, String defaultMessage) {
        this.code = code;
        this.defaultMessage = defaultMessage;
    }
    
    /**
     * Get the error/status code for API responses
     * @return String code like "KYC_VALID" or "KYC_INVALID_SIGNATURE"
     */
    public String getCode() {
        return code;
    }
    
    /**
     * Get the default human-readable message
     * @return Default message describing the validation result
     */
    public String getDefaultMessage() {
        return defaultMessage;
    }
    
    /**
     * Check if validation was successful
     * @return true if result is VALID
     */
    public boolean isSuccess() {
        return this == VALID;
    }
    
    /**
     * Check if this is a certificate-related error
     * @return true if error relates to certificate validation
     */
    public boolean isCertificateError() {
        return this == EXPIRED_CERTIFICATE || 
               this == REVOKED_CERTIFICATE || 
               this == INVALID_CERTIFICATE_CHAIN;
    }
    
    /**
     * Check if this is an input validation error
     * @return true if error relates to input validation
     */
    public boolean isInputError() {
        return this == FILE_TOO_LARGE || 
               this == INVALID_FILE_TYPE || 
               this == EMPTY_FILE ||
               this == XML_PARSE_ERROR;
    }
}
