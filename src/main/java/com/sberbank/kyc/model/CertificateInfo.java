package com.sberbank.kyc.model;

import java.time.Instant;

public class CertificateInfo {
    private String subjectDN;
    private String issuerDN;
    private String serialNumber;
    private Instant validFrom;
    private Instant validTo;
    private String signatureAlgorithm;
    
    public void setSubjectDN(String dn) { this.subjectDN = dn; }
    public void setIssuerDN(String dn) { this.issuerDN = dn; }
    public void setSerialNumber(String sn) { this.serialNumber = sn; }
    public void setValidFrom(Instant from) { this.validFrom = from; }
    public void setValidTo(Instant to) { this.validTo = to; }
    public void setSignatureAlgorithm(String algo) { this.signatureAlgorithm = algo; }
}
