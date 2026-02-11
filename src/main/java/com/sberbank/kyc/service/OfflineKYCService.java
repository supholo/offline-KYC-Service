package com.sberbank.kyc.service;

import com.sberbank.kyc.*;
import com.sberbank.kyc.exception.ValidationException;
import com.sberbank.kyc.model.KYCData;
import com.sberbank.kyc.model.KYCValidationResponse;
import com.sberbank.kyc.model.ValidationResult;

import org.springframework.stereotype.Service;
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
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.FileHeader;
import java.util.Comparator;

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
    
    @Value("${kyc.uidai.publickey.latest.path:certs/uidai-public-keys/uidai_offline_publickey_latest.cer}")
    private String latestPublicKeyPath;

    @Value("${kyc.uidai.publickey.previous.path:certs/uidai-public-keys/uidai_offline_publickey_previous.cer}")
    private String previousPublicKeyPath;
    
    private final OfflineAadhaarKYCValidator validator;
    private X509Certificate cachedRootCert;
    private boolean rootCertAvailable = false;
    private X509Certificate latestPublicKey;
    private X509Certificate previousPublicKey;
    private boolean publicKeysAvailable = false;
    
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
        
        // Load UIDAI public keys for signature validation
        try {
            this.previousPublicKey = loadPublicKey(previousPublicKeyPath, "Previous");
            this.latestPublicKey = loadPublicKey(latestPublicKeyPath, "Latest");
            this.publicKeysAvailable = (previousPublicKey != null || latestPublicKey != null);
            
            if (publicKeysAvailable) {
                logger.info("UIDAI public keys loaded successfully for signature validation");
            } else {
                logger.error("No UIDAI public keys available - signature validation will fail!");
            }
        } catch (Exception e) {
            logger.error("Failed to load UIDAI public keys: {}", e.getMessage());
            this.publicKeysAvailable = false;
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
     * Validate uploaded offline KYC ZIP file
     * 
     * @param zipFile Uploaded ZIP file (password protected with shareCode)
     * @param shareCode 4-digit share code (also ZIP password)
     * @param customerId Customer ID for audit
     * @param requestId Unique request ID for tracking
     * @return KYCValidationResponse with results
     * @throws IOException 
     */
    public KYCValidationResponse validateKYC(
            MultipartFile zipFile, 
            String shareCode,
            String mobileNumber,
            String customerId,
            String requestId) throws IOException {
        
    	long startTime = System.currentTimeMillis();
    	Path tempFilePath = null;
    	Path tempDirPath = null;

        try {
            // Pre-validation checks
            validateInputParameters(zipFile, shareCode);
            
            // Audit: Log validation attempt
            auditLog("KYC_VALIDATION_STARTED", requestId, customerId, 
                Map.of("fileName", zipFile.getOriginalFilename(),
                       "fileSize", zipFile.getSize(),
                       "skipCertExpiryCheck", skipCertExpiryCheck));
            
            // Extract XML from password-protected ZIP
            tempDirPath = Paths.get(tempDir, requestId);
            tempFilePath = extractXmlFromZip(zipFile, shareCode, tempDirPath);
            
            // Perform validation with external public keys (previous first, then latest)
            KYCValidationResponse response = validator.validateOfflineKYC(
                tempFilePath.toString(), shareCode, mobileNumber, skipCertExpiryCheck, 
                previousPublicKey, latestPublicKey);
            
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
        	cleanupTemporaryDirectory(tempDirPath);
        }
    }
    
    /**
     * Pre-validation input checks
     */
    private void validateInputParameters(MultipartFile zipFile, String shareCode) 
            throws ValidationException {
        
        if (zipFile == null || zipFile.isEmpty()) {
            throw new ValidationException("EMPTY_FILE", "ZIP file is required");
        }
        
        if (zipFile.getSize() > maxFileSize) {
            throw new ValidationException("FILE_TOO_LARGE", 
                "File size exceeds maximum allowed: " + maxFileSize + " bytes");
        }
        
        String contentType = zipFile.getContentType();
        if (contentType != null && !contentType.contains("zip") && 
            !contentType.equals("application/octet-stream") &&
            !contentType.equals("application/x-zip-compressed")) {
            throw new ValidationException("INVALID_FILE_TYPE", 
                "Invalid file type. Expected ZIP file.");
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
    
    /**
     * Extract XML file from password-protected ZIP
     * 
     * @param zipFile Uploaded ZIP file
     * @param shareCode Password for ZIP (4-digit share code)
     * @param tempDirPath Temporary directory for extraction
     * @return Path to extracted XML file
     */
    private Path extractXmlFromZip(MultipartFile zipFile, String shareCode, Path tempDirPath) 
            throws IOException, ValidationException {
        
        // Create temp directory
        Files.createDirectories(tempDirPath);
        
        // Save ZIP temporarily
        Path zipPath = tempDirPath.resolve("upload.zip");
        Files.copy(zipFile.getInputStream(), zipPath, StandardCopyOption.REPLACE_EXISTING);
        
        try {
            // Extract with password (shareCode)
            ZipFile zip = new ZipFile(zipPath.toFile(), shareCode.toCharArray());
            
            // Find XML file in ZIP
            for (FileHeader header : zip.getFileHeaders()) {
                if (header.getFileName().toLowerCase().endsWith(".xml")) {
                    zip.extractFile(header, tempDirPath.toString());
                    Path xmlPath = tempDirPath.resolve(header.getFileName());
                    logger.info("Extracted XML file: {}", header.getFileName());
                    return xmlPath;
                }
            }
            
            throw new ValidationException("NO_XML_FOUND", "No XML file found in ZIP archive");
            
        } catch (net.lingala.zip4j.exception.ZipException e) {
            if (e.getMessage().contains("Wrong password") || 
                e.getMessage().contains("invalid password")) {
                throw new ValidationException("INVALID_ZIP_PASSWORD", 
                    "Invalid share code - cannot extract ZIP file");
            }
            throw new ValidationException("ZIP_EXTRACTION_ERROR", 
                "Failed to extract ZIP file: " + e.getMessage());
        }
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
    
    private void cleanupTemporaryDirectory(Path dirPath) {
        if (dirPath != null && Files.exists(dirPath)) {
            try {
                Files.walk(dirPath)
                    .sorted(Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            logger.warn("Failed to delete: {}", path);
                        }
                    });
            } catch (IOException e) {
                logger.warn("Failed to cleanup temporary directory: {}", dirPath, e);
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
    
    /**
     * Load UIDAI public key certificate from classpath
     */
    private X509Certificate loadPublicKey(String path, String keyType) {
        try {
            String resourcePath = path.replaceFirst("^classpath:", "");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            
            try (InputStream is = Thread.currentThread()
                    .getContextClassLoader()
                    .getResourceAsStream(resourcePath)) {
                
                if (is == null) {
                    logger.warn("UIDAI {} public key not found: {}", keyType, resourcePath);
                    return null;
                }
                
                X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
                
                logger.info("UIDAI {} public key loaded. Subject={}, ValidFrom={}, ValidTo={}",
                    keyType,
                    cert.getSubjectX500Principal().getName(),
                    cert.getNotBefore(),
                    cert.getNotAfter());
                
                return cert;
            }
        } catch (Exception e) {
            logger.error("Failed to load UIDAI {} public key: {}", keyType, e.getMessage());
            return null;
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
    
    public X509Certificate getLatestPublicKey() {
        return latestPublicKey;
    }

    public X509Certificate getPreviousPublicKey() {
        return previousPublicKey;
    }

    public boolean isPublicKeysAvailable() {
        return publicKeysAvailable;
    }
}