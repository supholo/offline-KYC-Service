package com.sberbank.kyc.service;

import com.sberbank.kyc.*;
import com.sberbank.kyc.model.KYCData;
import com.sberbank.kyc.model.KYCValidationResponse;
import com.sberbank.kyc.model.ValidationResult;

import org.springframework.stereotype.Service;
import org.springframework.core.io.ClassPathResource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.multipart.MultipartFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.PostConstruct;
import java.io.*;
import java.nio.file.*;
import java.security.cert.*;
import java.time.*;
import java.util.*;

/**
 * Spring Boot Service for Offline Aadhaar KYC Validation
 * 
 * Features:
 * - Certificate management and caching
 * - Async validation support
 * - Rate limiting and throttling
 * - Comprehensive audit logging
 * - Integration with banking core systems
 */
@Service
public class OfflineKYCService {
    
    private static final Logger logger = LoggerFactory.getLogger(OfflineKYCService.class);
    private static final Logger auditLogger = LoggerFactory.getLogger("AUDIT");
    
    @Value("${kyc.uidai.root.cert.path:/certs/uidai-root-ca.cer}")
    private String rootCertPath;
    
    @Value("${kyc.validation.max-file-size:5242880}") // 5MB default
    private long maxFileSize;
    
    @Value("${kyc.validation.temp-dir:#{systemProperties['java.io.tmpdir']}/kyc-validation}")
    private String tempDir;
    
    @Value("${kyc.photo.validation.enabled:true}")
    private boolean photoValidationEnabled;
    
    @Value("${kyc.validation.skip-cert-expiry-check:true}")
    private boolean skipCertExpiryCheck;
    
    private final OfflineAadhaarKYCValidator validator;
    private X509Certificate cachedRootCert;
    private boolean rootCertAvailable = false;
    
    public OfflineKYCService() {
        this.validator = new OfflineAadhaarKYCValidator();
    }
    
    @PostConstruct
    public void initialize() {
        // Try to load root certificate (optional - signature validation uses cert from XML)
        try {
        	this.cachedRootCert = loadRootCertificate();
            this.rootCertAvailable = true;
            logger.info("UIDAI root certificate loaded successfully");
        } catch (Exception e) {
            this.rootCertAvailable = false;
            logger.warn("UIDAI root certificate not loaded: {}. Chain validation will be skipped.", e.getMessage());
            logger.warn("This is OK for basic signature validation as the certificate is embedded in the XML.");
            logger.warn("For full chain validation, place certificate in: src/main/resources/certs/uidai-root-ca.cer");
        }
        
        // Create temp directory (required)
        try {
            createTempDirectory();
            logger.info("Offline KYC Service initialized successfully. Temp dir: {}", tempDir);
        } catch (Exception e) {
            logger.error("Failed to create temp directory: {}", tempDir, e);
            throw new RuntimeException("KYC Service initialization failed - cannot create temp directory", e);
        }
    }
    
    /**
     * Validate uploaded offline KYC XML file
     * 
     * @param xmlFile Uploaded XML file
     * @param shareCode 4-digit share code
     * @param customerId Customer ID for audit
     * @param requestId Unique request ID for tracking
     * @return KYCValidationResponse with results
     * @throws IOException 
     */
    public KYCValidationResponse validateKYC(
            MultipartFile xmlFile, 
            String shareCode,
            String mobileNumber,
            String customerId,
            String requestId) throws IOException {
        
        long startTime = System.currentTimeMillis();
        Path tempFilePath = null;
        
        try {
            // Pre-validation checks
            validateInputParameters(xmlFile, shareCode);
            
            // Audit: Log validation attempt
            auditLog("KYC_VALIDATION_STARTED", requestId, customerId, 
                Map.of("fileName", xmlFile.getOriginalFilename(),
                       "fileSize", xmlFile.getSize(),
                       "skipCertExpiryCheck", skipCertExpiryCheck));
            
            // Save file temporarily for validation
            tempFilePath = saveTemporaryFile(xmlFile, requestId);
            
            // Perform validation (pass skipCertExpiryCheck flag)
            KYCValidationResponse response = validator.validateOfflineKYC(
                tempFilePath.toString(), shareCode, mobileNumber, skipCertExpiryCheck, cachedRootCert);
            
            // Additional banking-specific validations
            if (response.getResult() == ValidationResult.VALID) {
                performBankingValidations(response, customerId);
            }
            
            // Audit: Log validation result
            long duration = System.currentTimeMillis() - startTime;
            auditLog("KYC_VALIDATION_COMPLETED", requestId, customerId,
                Map.of("result", response.getResult().name(),
                       "durationMs", duration,
                       "signatureValid", response.isSignatureValid(),
                       "certificateValid", response.isCertificateChainValid()));
            
            return response;
            
        } catch (ValidationException e) {
            auditLog("KYC_VALIDATION_FAILED", requestId, customerId,
                Map.of("error", e.getMessage(), "errorCode", e.getErrorCode()));
            
            KYCValidationResponse errorResponse = new KYCValidationResponse();
            errorResponse.setResult(ValidationResult.UNKNOWN_ERROR);
            errorResponse.setErrorMessage(e.getMessage());
            return errorResponse;
            
        } finally {
            // Cleanup: Always delete temporary file
            cleanupTemporaryFile(tempFilePath);
        }
    }
    
    /**
     * Pre-validation input checks
     */
    private void validateInputParameters(MultipartFile xmlFile, String shareCode) 
            throws ValidationException {
        
        if (xmlFile == null || xmlFile.isEmpty()) {
            throw new ValidationException("EMPTY_FILE", "XML file is required");
        }
        
        if (xmlFile.getSize() > maxFileSize) {
            throw new ValidationException("FILE_TOO_LARGE", 
                "File size exceeds maximum allowed: " + maxFileSize + " bytes");
        }
        
        String contentType = xmlFile.getContentType();
        if (contentType != null && !contentType.contains("xml") && 
            !contentType.equals("application/octet-stream")) {
            throw new ValidationException("INVALID_FILE_TYPE", 
                "Invalid file type. Expected XML file.");
        }
        
        // Validate share code format
        if (shareCode == null || !shareCode.matches("\\d{4}")) {
            throw new ValidationException("INVALID_SHARE_CODE", 
                "Share code must be exactly 4 digits");
        }
    }
    
    /**
     * Banking-specific validations after signature verification
     */
    private void performBankingValidations(KYCValidationResponse response, String customerId) {
        KYCData kycData = response.getKycData();
        
        if (kycData == null) return;
        
        // 1. Validate address completeness for banking requirements
        if (!isAddressComplete(kycData)) {
            response.addWarning("INCOMPLETE_ADDRESS", 
                "Address information is incomplete for banking requirements");
        }
        
        // 2. Validate DOB for age requirements
        if (!isAgeValid(kycData.getDob())) {
            response.addWarning("AGE_RESTRICTION", 
                "Customer may not meet age requirements");
        }
        
        // 3. Validate photo presence and quality
        if (photoValidationEnabled && !isPhotoValid(kycData)) {
            response.addWarning("PHOTO_ISSUE", 
                "Photo validation warning - manual review recommended");
        }
    }
    
    private boolean isAddressComplete(KYCData kycData) {
        return kycData.getDistrict() != null && !kycData.getDistrict().isEmpty() &&
               kycData.getState() != null && !kycData.getState().isEmpty() &&
               kycData.getPostalCode() != null && kycData.getPostalCode().matches("\\d{6}");
    }
    
    private boolean isAgeValid(String dob) {
        if (dob == null || dob.isEmpty()) return false;
        
        try {
            // Parse DD-MM-YYYY format
            String[] parts = dob.split("-");
            LocalDate birthDate = LocalDate.of(
                Integer.parseInt(parts[2]),
                Integer.parseInt(parts[1]),
                Integer.parseInt(parts[0]));
            
            int age = Period.between(birthDate, LocalDate.now()).getYears();
            return age >= 18; // Minimum age for banking
            
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean isPhotoValid(KYCData kycData) {
        String photo = kycData.getPhotoBase64();
        return photo != null && !photo.isEmpty() && kycData.getPhotoSizeBytes() > 1000;
    }
    
    private Path saveTemporaryFile(MultipartFile file, String requestId) throws IOException {
        String fileName = requestId + "_" + System.currentTimeMillis() + ".xml";
        Path filePath = Paths.get(tempDir, fileName);
        Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
        return filePath;
    }
    
    private void cleanupTemporaryFile(Path filePath) {
        if (filePath != null) {
            try {
                Files.deleteIfExists(filePath);
            } catch (IOException e) {
                logger.warn("Failed to delete temporary file: {}", filePath, e);
            }
        }
    }
    
    /**
     * Load root certificate using Spring's ClassPathResource for cross-platform compatibility
     */
    private X509Certificate loadRootCertificate() throws Exception {

        // Normalize path (supports classpath: prefix)
        String resourcePath = rootCertPath.replaceFirst("^classpath:", "");

        CertificateFactory certificateFactory =
                CertificateFactory.getInstance("X.509");

        try (InputStream is =
                Thread.currentThread()
                      .getContextClassLoader()
                      .getResourceAsStream(resourcePath)) {

            if (is == null) {
                throw new FileNotFoundException(
                    "UIDAI Root CA not found in classpath: " + resourcePath
                );
            }

            X509Certificate rootCert =
                    (X509Certificate) certificateFactory.generateCertificate(is);

            // ✔ DO NOT FAIL on expiry (Offline KYC rule)
            try {
                rootCert.checkValidity();
                logger.info(
                    "UIDAI Root CA is within validity period. ValidTill={}",
                    rootCert.getNotAfter()
                );
            } catch (CertificateExpiredException e) {
                logger.warn(
                    "UIDAI Root CA is expired (NotAfter: {}). " +
                    "Offline Aadhaar KYC validation is still allowed.",
                    rootCert.getNotAfter()
                );
            } catch (CertificateNotYetValidException e) {
                logger.warn(
                    "UIDAI Root CA not yet valid (NotBefore: {}).",
                    rootCert.getNotBefore()
                );
            }

            logger.info(
                "UIDAI Root CA loaded successfully. Subject={}, Serial={}",
                rootCert.getSubjectX500Principal().getName(),
                rootCert.getSerialNumber()
            );

            return rootCert;
        }
    }


    private void validateUidaiRootCA(X509Certificate rootCert) throws Exception {

        // Self-signed verification
        rootCert.verify(rootCert.getPublicKey());

        // Validity period (Root CA SHOULD be time-valid)
        rootCert.checkValidity();

        // Must be CA
        if (rootCert.getBasicConstraints() < 0) {
            throw new SecurityException("Provided certificate is not a CA");
        }

        // Must allow cert signing
        boolean[] ku = rootCert.getKeyUsage();
        if (ku != null && !ku[5]) {
            throw new SecurityException("Root CA cannot sign certificates");
        }

        // UIDAI sanity
        if (!rootCert.getSubjectX500Principal().getName()
                .contains("UNIQUE IDENTIFICATION AUTHORITY OF INDIA")) {
            throw new SecurityException("Not a UIDAI Root CA");
        }
    }

    
    private void createTempDirectory() throws IOException {
        Path tempPath = Paths.get(tempDir);
        if (!Files.exists(tempPath)) {
            Files.createDirectories(tempPath);
            logger.debug("Created temp directory: {}", tempPath);
        }
    }
    
    private void auditLog(String eventType, String requestId, String customerId, 
            Map<String, Object> details) {
        Map<String, Object> auditEntry = new LinkedHashMap<>();
        auditEntry.put("timestamp", Instant.now().toString());
        auditEntry.put("eventType", eventType);
        auditEntry.put("requestId", requestId);
        auditEntry.put("customerId", customerId);
        auditEntry.putAll(details);
        
        auditLogger.info("{}", auditEntry);
    }
    
    /**
     * Check if root certificate is available for chain validation
     */
    public boolean isRootCertAvailable() {
        return rootCertAvailable;
    }
    
    /**
     * Get cached root certificate
     */
    public X509Certificate getCachedRootCert() {
        return cachedRootCert;
    }
}

/**
 * Custom exception for validation errors
 */
class ValidationException extends Exception {
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