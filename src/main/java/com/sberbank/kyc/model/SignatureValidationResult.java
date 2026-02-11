package com.sberbank.kyc.model;

import java.security.cert.X509Certificate;

/**
 * Result of XML/QR signature validation
 */
public class SignatureValidationResult {
    private boolean valid;
    private String errorMessage;
    private X509Certificate signingCertificate;
    private CertificateInfo certificateInfo;
    private String algorithm;  // Signature algorithm used (e.g., SHA256withRSA)
    
    public boolean isValid() { return valid; }
    public void setValid(boolean valid) { this.valid = valid; }
    
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    
    public X509Certificate getSigningCertificate() { return signingCertificate; }
    public void setSigningCertificate(X509Certificate signingCertificate) { this.signingCertificate = signingCertificate; }
    
    public CertificateInfo getCertificateInfo() { return certificateInfo; }
    public void setCertificateInfo(CertificateInfo certificateInfo) { this.certificateInfo = certificateInfo; }
    
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
}