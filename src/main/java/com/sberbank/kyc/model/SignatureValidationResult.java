package com.sberbank.kyc.model;

import java.security.cert.X509Certificate;

public class SignatureValidationResult {
    private boolean valid;
    private String errorMessage;
    private X509Certificate signingCertificate;
    private CertificateInfo certificateInfo;
    
    public void setValid(boolean v) { this.valid = v; }
    public boolean isValid() { return valid; }
    public void setErrorMessage(String msg) { this.errorMessage = msg; }
    public String getErrorMessage() { return errorMessage; }
    public void setSigningCertificate(X509Certificate cert) { this.signingCertificate = cert; }
    public X509Certificate getSigningCertificate() { return signingCertificate; }
    public void setCertificateInfo(CertificateInfo info) { this.certificateInfo = info; }
    public CertificateInfo getCertificateInfo() { return certificateInfo; }
}
