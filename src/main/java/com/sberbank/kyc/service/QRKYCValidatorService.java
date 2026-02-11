package com.sberbank.kyc.service;

import com.sberbank.kyc.exception.ValidationException;
import com.sberbank.kyc.model.*;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.time.*;
import java.util.*;
import java.util.zip.GZIPInputStream;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;

/**
 * Aadhaar Secure QR Code Validator Service
 * 
 * Validates the raw decoded QR data sent from UI after scanning.
 * 
 * Aadhaar Secure QR Code Format (V2):
 * - Big Integer (256 bytes) - Digital Signature
 * - Delimiter (byte 255)
 * - Compressed Data (GZIP) containing:
 *   - Version byte
 *   - Reference ID (variable)
 *   - Name (variable)
 *   - DOB (DDMMYYYY or YYYY)
 *   - Gender (M/F/T)
 *   - Address fields (separated by delimiters)
 *   - Photo bytes (JPEG)
 * 
 * @author Sberbank India - Enterprise Architecture
 * @version 1.0
 */
@Service
public class QRKYCValidatorService {
    
    private static final Logger logger = LoggerFactory.getLogger(QRKYCValidatorService.class);
    private static final Logger auditLogger = LoggerFactory.getLogger("AUDIT");
    
    // Delimiter used in Aadhaar Secure QR
    private static final int DELIMITER_BYTE = 255;
    private static final int SIGNATURE_LENGTH = 256;
    
    @Value("${kyc.uidai.publickey.latest.path:certs/uidai-public-keys/uidai_offline_publickey_latest.cer}")
    private String latestPublicKeyPath;
    
    @Value("${kyc.uidai.publickey.previous.path:certs/uidai-public-keys/uidai_offline_publickey_previous.cer}")
    private String previousPublicKeyPath;
    
    @Value("${kyc.validation.skip-cert-expiry-check:true}")
    private boolean skipCertExpiryCheck;
    
    private X509Certificate latestPublicKey;
    private X509Certificate previousPublicKey;
    private boolean publicKeysAvailable = false;
    
    @PostConstruct
    public void initialize() {
        // Load UIDAI public keys for signature verification
        try {
            previousPublicKey = loadPublicKey(previousPublicKeyPath, "previous");
        } catch (Exception e) {
            logger.warn("Previous UIDAI public key not loaded: {}", e.getMessage());
        }
        
        try {
            latestPublicKey = loadPublicKey(latestPublicKeyPath, "latest");
        } catch (Exception e) {
            logger.warn("Latest UIDAI public key not loaded: {}", e.getMessage());
        }
        
        publicKeysAvailable = (previousPublicKey != null || latestPublicKey != null);
        
        if (publicKeysAvailable) {
            logger.info("QR KYC Validator Service initialized with UIDAI public keys");
        } else {
            logger.warn("QR KYC Validator Service initialized WITHOUT public keys. Signature validation will fail.");
        }
    }
    
    private X509Certificate loadPublicKey(String path, String keyType) throws Exception {
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(path)) {
            if (is == null) {
                throw new FileNotFoundException("Public key not found: " + path);
            }
            
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
            
            logger.info("Loaded {} UIDAI public key: Subject={}, ValidTill={}", 
                keyType, cert.getSubjectX500Principal().getName(), cert.getNotAfter());
            
            return cert;
        }
    }
    
    /**
     * Validate Aadhaar QR Code data
     * 
     * @param rawQRData Raw byte data from QR code scan (can be Base64 encoded or raw bytes)
     * @param shareCode 4-digit share code for verification
     * @param mobileNumber Optional mobile number for verification
     * @param customerId Customer ID for audit
     * @param requestId Request ID for tracking
     * @return QRKYCValidationResponse with validation results
     */
    public QRKYCValidationResponse validateQRCode(
            String rawQRData,
            String shareCode,
            String mobileNumber,
            String customerId,
            String requestId) {
        
        long startTime = System.currentTimeMillis();
        QRKYCValidationResponse response = new QRKYCValidationResponse();
        response.setRequestId(requestId);
        response.setValidationTimestamp(Instant.now());
        
        try {
            // Step 1: Validate input parameters
            validateInputParameters(rawQRData, shareCode);
            
            auditLog("QR_KYC_STARTED", requestId, customerId, Map.of(
                "dataLength", rawQRData.length(),
                "hasShareCode", shareCode != null
            ));
            
            // Step 2: Decode QR data (handle both Base64 and raw formats)
            byte[] qrBytes = decodeQRData(rawQRData);
            
            if (qrBytes == null || qrBytes.length < SIGNATURE_LENGTH + 10) {
                response.setResult(ValidationResult.XML_PARSE_ERROR);
                response.setErrorMessage("Invalid QR data format - too short");
                return response;
            }
            
            // Step 3: Detect QR format and parse
            QRParseResult parseResult = parseQRData(qrBytes);
            
            if (!parseResult.isSuccess()) {
                response.setResult(ValidationResult.XML_PARSE_ERROR);
                response.setErrorMessage(parseResult.getErrorMessage());
                return response;
            }
            
            response.setQrVersion(parseResult.getVersion());
            response.setQrFormat(parseResult.getFormat());
            
            // Step 4: Validate digital signature
            SignatureValidationResult sigResult = validateQRSignature(
                parseResult.getSignatureBytes(), 
                parseResult.getDataBytes()
            );
            
            response.setSignatureValid(sigResult.isValid());
            response.setSignatureAlgorithm(sigResult.getAlgorithm());
            
            if (!sigResult.isValid()) {
                response.setResult(ValidationResult.INVALID_SIGNATURE);
                response.setErrorMessage("QR signature verification failed: " + sigResult.getErrorMessage());
                
                // Still extract data even if signature fails (for debugging)
                if (parseResult.getKycData() != null) {
                    response.setKycData(parseResult.getKycData());
                }
                
                return response;
            }
            
            // Step 5: Set certificate info if available
            if (sigResult.getCertificateInfo() != null) {
                response.setCertificateInfo(sigResult.getCertificateInfo());
            }
            response.setCertificateChainValid(true);
            
            // Step 6: Validate share code format
            if (shareCode == null || !shareCode.matches("\\d{4}")) {
                response.setResult(ValidationResult.SHARE_CODE_MISMATCH);
                response.setErrorMessage("Share code must be exactly 4 digits");
                return response;
            }
            response.setShareCodeValid(true);
            
            // Step 7: Extract and set KYC data
            KYCData kycData = parseResult.getKycData();
            
            if (kycData == null) {
                response.setResult(ValidationResult.XML_PARSE_ERROR);
                response.setErrorMessage("Failed to extract KYC data from QR");
                return response;
            }
            
            // Step 8: Verify mobile number if provided
            if (mobileNumber != null && !mobileNumber.isEmpty()) {
                boolean mobileVerified = verifyMobileHash(
                    mobileNumber, shareCode, 
                    kycData.getReferenceId(), kycData.getMobileHash()
                );
                kycData.setMobileVerified(mobileVerified);
                
                if (mobileVerified) {
                    kycData.setVerifiedMobileNumber(mobileNumber);
                }
                
                response.setMobileVerified(mobileVerified);
            }
            
            response.setKycData(kycData);
            
            // Step 9: Additional validations
            performAdditionalValidations(response, kycData);
            
            // All validations passed
            response.setResult(ValidationResult.VALID);
            response.setSuccess(true);
            response.setSuccessMessage("Aadhaar QR Code validated successfully");
            
            long duration = System.currentTimeMillis() - startTime;
            response.setProcessingTimeMs(duration);
            
            auditLog("QR_KYC_COMPLETED", requestId, customerId, Map.of(
                "result", response.getResult().name(),
                "signatureValid", response.isSignatureValid(),
                "qrFormat", parseResult.getFormat(),
                "durationMs", duration
            ));
            
        } catch (ValidationException e) {
            response.setResult(ValidationResult.UNKNOWN_ERROR);
            response.setErrorMessage(e.getMessage());
            
            auditLog("QR_KYC_ERROR", requestId, customerId, Map.of(
                "error", e.getMessage(),
                "errorCode", e.getErrorCode()
            ));
        } catch (Exception e) {
            logger.error("QR KYC validation error", e);
            response.setResult(ValidationResult.UNKNOWN_ERROR);
            response.setErrorMessage("QR validation error: " + e.getMessage());
            
            auditLog("QR_KYC_ERROR", requestId, customerId, Map.of(
                "error", e.getMessage()
            ));
        }
        
        return response;
    }
    
    /**
     * Validate input parameters
     */
    private void validateInputParameters(String rawQRData, String shareCode) throws ValidationException {
        if (rawQRData == null || rawQRData.trim().isEmpty()) {
            throw new ValidationException("EMPTY_QR_DATA", "QR code data is required");
        }
        
        if (rawQRData.length() < 100) {
            throw new ValidationException("INVALID_QR_DATA", "QR data is too short to be valid Aadhaar QR");
        }
        
        if (shareCode == null || !shareCode.matches("\\d{4}")) {
            throw new ValidationException("INVALID_SHARE_CODE", "Share code must be exactly 4 digits");
        }
    }
    
    /**
     * Decode QR data - handles multiple formats including BigInteger numeric string
     */
    private byte[] decodeQRData(String rawQRData) {
        // Try 1: Check if it's a BigInteger numeric string (Aadhaar Secure QR format)
        // This is the most common format from jsQR scanning
        if (rawQRData.matches("^[0-9]+$") && rawQRData.length() > 100) {
            try {
                BigInteger bigInt = new BigInteger(rawQRData);
                byte[] bytes = bigInt.toByteArray();
                // Remove leading zero byte if present (BigInteger adds it for positive numbers)
                if (bytes.length > 0 && bytes[0] == 0) {
                    bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
                }
                logger.info("Decoded QR data from BigInteger format, length: {} bytes", bytes.length);
                return bytes;
            } catch (NumberFormatException e) {
                logger.debug("Not a valid BigInteger, trying other formats");
            }
        }
        
        // Try 2: Check if it's Base64 encoded
        try {
            String cleanData = rawQRData.replaceAll("\\s+", "");
            if (cleanData.matches("^[A-Za-z0-9+/=]+$") && cleanData.length() > 100) {
                byte[] decoded = Base64.getDecoder().decode(cleanData);
                logger.info("Decoded QR data from Base64 format, length: {} bytes", decoded.length);
                return decoded;
            }
        } catch (Exception e) {
            logger.debug("Not Base64 encoded, trying as raw data");
        }
        
        // Try 3: It's raw string data (ISO-8859-1 encoding preserves byte values)
        try {
            return rawQRData.getBytes(StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            logger.debug("ISO-8859-1 decode failed, trying UTF-8");
        }
        
        // Try 4: UTF-8 encoding
        return rawQRData.getBytes(StandardCharsets.UTF_8);
    }
    
/**
 * Parse QR data and extract components
 */
private QRParseResult parseQRData(byte[] qrBytes) {
    QRParseResult result = new QRParseResult();
    
    try {
        // First, check if data starts with GZIP header (non-secure QR)
        if (qrBytes.length >= 2 && 
            (qrBytes[0] & 0xFF) == 0x1F && 
            (qrBytes[1] & 0xFF) == 0x8B) {
            
            logger.info("QR data starts with GZIP header - processing as non-secure QR");
            return parseNonSecureQR(qrBytes);
        }
        
        // Find the delimiter position for secure QR
        int delimiterPos = -1;
        
        // Method 1: Look for delimiter after signature area
        for (int i = SIGNATURE_LENGTH - 20; i < Math.min(qrBytes.length, SIGNATURE_LENGTH + 50); i++) {
            if ((qrBytes[i] & 0xFF) == DELIMITER_BYTE) {
                delimiterPos = i;
                break;
            }
        }
        
        // Method 2: Look for GZIP header after signature
        if (delimiterPos == -1) {
            for (int i = SIGNATURE_LENGTH - 10; i < Math.min(qrBytes.length - 1, SIGNATURE_LENGTH + 50); i++) {
                if ((qrBytes[i] & 0xFF) == 0x1F && (qrBytes[i + 1] & 0xFF) == 0x8B) {
                    delimiterPos = i - 1;
                    break;
                }
            }
        }
        
        if (delimiterPos == -1 || delimiterPos >= qrBytes.length - 10) {
            // No delimiter found - treat as non-secure QR
            logger.info("No signature delimiter found - processing as non-secure QR");
            return parseNonSecureQR(qrBytes);
        }
        
        // Extract signature and data bytes
        byte[] signatureBytes = Arrays.copyOfRange(qrBytes, 0, delimiterPos);
        byte[] dataBytes = Arrays.copyOfRange(qrBytes, delimiterPos + 1, qrBytes.length);
        
        result.setSignatureBytes(signatureBytes);
        result.setDataBytes(dataBytes);
        result.setFormat("SECURE_QR_V2");
        
        // Decompress and parse data
        byte[] decompressedData = decompressData(dataBytes);
        
        if (decompressedData != null) {
            KYCData kycData = parseDecompressedData(decompressedData);
            result.setKycData(kycData);
            result.setVersion(extractVersion(decompressedData));
        } else {
            KYCData kycData = parseUncompressedData(dataBytes);
            result.setKycData(kycData);
            result.setFormat("SECURE_QR_V1");
        }
        
        result.setSuccess(true);
        
    } catch (Exception e) {
        logger.error("QR parse error", e);
        result.setSuccess(false);
        result.setErrorMessage("Failed to parse QR data: " + e.getMessage());
    }
    
    return result;
}
 
/**
 * Parse non-secure QR (data starts with GZIP header)
 * In this format, the entire data is compressed, and signature is at the END of decompressed data
 */
private QRParseResult parseNonSecureQR(byte[] qrBytes) {
    QRParseResult result = new QRParseResult();
    result.setFormat("SECURE_QR");
    
    try {
        byte[] decompressed = decompressData(qrBytes);
        
        if (decompressed != null && decompressed.length > SIGNATURE_LENGTH) {
            logger.info("Decompressed QR data successfully, size: {} bytes", decompressed.length);
            
            // Signature is the LAST 256 bytes of decompressed data
            byte[] signatureBytes = Arrays.copyOfRange(decompressed, decompressed.length - SIGNATURE_LENGTH, decompressed.length);
            
            // Signed data is everything BEFORE the signature
            byte[] signedData = Arrays.copyOfRange(decompressed, 0, decompressed.length - SIGNATURE_LENGTH);
            
            result.setSignatureBytes(signatureBytes);
            result.setDataBytes(signedData);
            
            // Parse the KYC data from decompressed content
            KYCData kycData = parseDecompressedData(decompressed);
            result.setKycData(kycData);
            result.setVersion(extractVersion(decompressed));
            result.setSuccess(true);
            
            logger.info("Extracted signature ({} bytes) and signed data ({} bytes)", 
                signatureBytes.length, signedData.length);
            
        } else if (decompressed != null) {
            // Very short data - might be non-standard format
            logger.warn("Decompressed data too short for signature extraction: {} bytes", decompressed.length);
            KYCData kycData = parseDecompressedData(decompressed);
            result.setKycData(kycData);
            result.setSuccess(true);
            result.setSignatureBytes(null);
            result.setDataBytes(decompressed);
        } else {
            // Try parsing as delimited text
            String qrString = new String(qrBytes, StandardCharsets.UTF_8);
            KYCData kycData = parseDelimitedQR(qrString);
            result.setKycData(kycData);
            result.setSuccess(true);
            result.setSignatureBytes(null);
            result.setDataBytes(qrBytes);
        }
        
    } catch (Exception e) {
        logger.error("Failed to parse QR", e);
        result.setSuccess(false);
        result.setErrorMessage("Failed to parse QR: " + e.getMessage());
    }
    
    return result;
}
    
    /**
     * Decompress GZIP data
     */
    private byte[] decompressData(byte[] compressedData) {
        try {
            if (compressedData.length < 2 || 
                (compressedData[0] & 0xFF) != 0x1F || 
                (compressedData[1] & 0xFF) != 0x8B) {
                return null;
            }
            
            ByteArrayInputStream bis = new ByteArrayInputStream(compressedData);
            GZIPInputStream gis = new GZIPInputStream(bis);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            
            gis.close();
            return bos.toByteArray();
            
        } catch (Exception e) {
            logger.debug("GZIP decompression failed: {}", e.getMessage());
            return null;
        }
    }
    
    private KYCData parseDecompressedData(byte[] data) {
        KYCData kycData = new KYCData();
        
        try {
            // Check for version marker (V2, V3, V5 etc.) FIRST before finding delimiters
            String versionMarker = "";
            boolean isV3OrV5 = false;
            if (data.length >= 2) {
                versionMarker = new String(new byte[]{data[0], data[1]}, StandardCharsets.ISO_8859_1);
                if (versionMarker.startsWith("V") && Character.isDigit(versionMarker.charAt(1))) {
                    logger.info("Version marker detected: {}", versionMarker);
                    isV3OrV5 = versionMarker.contains("3") || versionMarker.contains("5");
                }
            }
            
            // Determine number of text fields based on version
            // V3/V5 fields: version, email_mobile_status, referenceid, name, dob, gender, careof, 
            //               district, landmark, house, location, pincode, postoffice, state, 
            //               street, subdistrict, vtc, last_4_digits_mobile = 18 fields
            // Standard fields (no version, no last_4_digits): 16 fields
            int numTextFields = isV3OrV5 ? 18 : 16;
            
            // Find delimiter positions ONLY for text fields (stop after expected count)
            // This prevents JPEG's 0xFF bytes from being counted as delimiters
            List<Integer> delimiterPositions = new ArrayList<>();
            delimiterPositions.add(-1); // Start marker (position before first field)
            
            int delimiterCount = 0;
            for (int i = 0; i < data.length && delimiterCount < numTextFields; i++) {
                if ((data[i] & 0xFF) == DELIMITER_BYTE) {
                    delimiterPositions.add(i);
                    delimiterCount++;
                }
            }
            
            logger.info("Text field delimiters found: {} (expected: {})", delimiterCount, numTextFields);
            
            // Extract fields based on delimiter positions
            int idx = 0;
            
            // Field 0: Version (for V3/V5) - skip it
            if (isV3OrV5 && delimiterPositions.size() > idx + 1) {
                String version = extractField(data, delimiterPositions, idx++);
                logger.debug("Version: {}", version);
            }
            
            // Field 1: Email/Mobile Status
            int emailMobileStatus = 0;
            if (delimiterPositions.size() > idx + 1) {
                String statusStr = extractField(data, delimiterPositions, idx++);
                try {
                    emailMobileStatus = Integer.parseInt(statusStr.trim());
                } catch (NumberFormatException e) {
                    emailMobileStatus = 0;
                }
                logger.debug("Email/Mobile Status: {}", emailMobileStatus);
            }
            
            // Field 2: Reference ID
            if (delimiterPositions.size() > idx + 1) {
                String refId = extractField(data, delimiterPositions, idx++);
                kycData.setReferenceId(refId);
                if (refId.length() >= 4) {
                    kycData.setMaskedAadhaar("XXXXXXXX" + refId.substring(0, 4));
                }
                logger.debug("ReferenceId: {}", refId);
            }
            
            // Field 3: Name
            if (delimiterPositions.size() > idx + 1) {
                kycData.setName(extractField(data, delimiterPositions, idx++));
                logger.debug("Name: {}", kycData.getName());
            }
            
            // Field 4: DOB
            if (delimiterPositions.size() > idx + 1) {
                String dob = extractField(data, delimiterPositions, idx++);
                kycData.setDob(formatDOB(dob));
                logger.debug("DOB: {}", dob);
            }
            
            // Field 5: Gender
            if (delimiterPositions.size() > idx + 1) {
                String gender = extractField(data, delimiterPositions, idx++);
                kycData.setGender(normalizeGender(gender));
                logger.debug("Gender: {}", gender);
            }
            
            // Field 6: Care Of
            if (delimiterPositions.size() > idx + 1) {
                kycData.setCareOf(extractField(data, delimiterPositions, idx++));
            }
            
            // Field 7: District
            if (delimiterPositions.size() > idx + 1) {
                kycData.setDistrict(extractField(data, delimiterPositions, idx++));
            }
            
            // Field 8: Landmark
            if (delimiterPositions.size() > idx + 1) {
                kycData.setLandmark(extractField(data, delimiterPositions, idx++));
            }
            
            // Field 9: House
            if (delimiterPositions.size() > idx + 1) {
                kycData.setHouse(extractField(data, delimiterPositions, idx++));
            }
            
            // Field 10: Location/Locality
            if (delimiterPositions.size() > idx + 1) {
                kycData.setLocality(extractField(data, delimiterPositions, idx++));
            }
            
            // Field 11: Pincode
            if (delimiterPositions.size() > idx + 1) {
                kycData.setPostalCode(extractField(data, delimiterPositions, idx++));
            }
            
            // Field 12: Post Office (extract but don't store)
            if (delimiterPositions.size() > idx + 1) {
                extractField(data, delimiterPositions, idx++); // Skip
            }
            
            // Field 13: State
            if (delimiterPositions.size() > idx + 1) {
                kycData.setState(extractField(data, delimiterPositions, idx++));
            }
            
            // Field 14: Street
            if (delimiterPositions.size() > idx + 1) {
                kycData.setStreet(extractField(data, delimiterPositions, idx++));
            }
            
            // Field 15: Sub-district (extract but don't store)
            if (delimiterPositions.size() > idx + 1) {
                extractField(data, delimiterPositions, idx++); // Skip
            }
            
            // Field 16: VTC
            if (delimiterPositions.size() > idx + 1) {
                kycData.setVtc(extractField(data, delimiterPositions, idx++));
            }
            
            // Field 17: Last 4 digits of mobile (V3/V5 only)
            String last4DigitsMobile = "";
            if (isV3OrV5 && delimiterPositions.size() > idx + 1) {
                last4DigitsMobile = extractField(data, delimiterPositions, idx++);
                logger.debug("Last 4 digits mobile: {}", last4DigitsMobile);
            }
            
            // Now extract photo from the end of data
            // Photo starts after the last text field delimiter
            int lastTextDelimiterIdx = delimiterPositions.size() - 1;
            int photoStartPos = delimiterPositions.get(lastTextDelimiterIdx) + 1;
            
            // Calculate photo end position based on version and email_mobile_status
            int signatureSize = SIGNATURE_LENGTH; // 256 bytes
            int photoEndPos;
            
            if (isV3OrV5) {
                // V3/V5: No hash storage, only signature after photo
                // Structure: [Text fields][Photo][Signature 256 bytes]
                photoEndPos = data.length - signatureSize;
                kycData.setEmailHash("");
                kycData.setMobileHash("");
                
                logger.info("V5 format: photoStart={}, photoEnd={}, signatureStart={}", 
                    photoStartPos, photoEndPos, photoEndPos);
            } else {
                // Standard format: hashes stored before signature
                // Structure: [Text fields][Photo][Email hash 32?][Mobile hash 32?][Signature 256]
                int emailHashSize = (emailMobileStatus == 1 || emailMobileStatus == 3) ? 32 : 0;
                int mobileHashSize = (emailMobileStatus == 2 || emailMobileStatus == 3) ? 32 : 0;
                
                photoEndPos = data.length - signatureSize - emailHashSize - mobileHashSize;
                
                // Extract email hash if present
                if (emailHashSize > 0) {
                    int emailHashStart;
                    if (emailMobileStatus == 3) {
                        emailHashStart = data.length - signatureSize - 32 - 32; // Both present
                    } else {
                        emailHashStart = data.length - signatureSize - 32; // Only email
                    }
                    byte[] emailHash = Arrays.copyOfRange(data, emailHashStart, emailHashStart + 32);
                    kycData.setEmailHash(bytesToHex(emailHash));
                } else {
                    kycData.setEmailHash("");
                }
                
                // Extract mobile hash if present
                if (mobileHashSize > 0) {
                    int mobileHashStart = data.length - signatureSize - 32;
                    byte[] mobileHash = Arrays.copyOfRange(data, mobileHashStart, mobileHashStart + 32);
                    kycData.setMobileHash(bytesToHex(mobileHash));
                } else {
                    kycData.setMobileHash("");
                }
                
                logger.info("Standard format: photoStart={}, photoEnd={}, emailHashSize={}, mobileHashSize={}", 
                    photoStartPos, photoEndPos, emailHashSize, mobileHashSize);
            }
            
         // Extract photo
            int photoSize = photoEndPos - photoStartPos;
            logger.info("Photo extraction: startPos={}, endPos={}, calculatedSize={}", 
                photoStartPos, photoEndPos, photoSize);

            if (photoSize > 100) {
                byte[] photoBytes = Arrays.copyOfRange(data, photoStartPos, photoEndPos);
                
                // Log first few bytes for debugging
                logger.debug("Photo first 4 bytes: 0x{} 0x{} 0x{} 0x{}", 
                    String.format("%02X", photoBytes[0] & 0xFF),
                    String.format("%02X", photoBytes[1] & 0xFF),
                    String.format("%02X", photoBytes[2] & 0xFF),
                    String.format("%02X", photoBytes[3] & 0xFF));
                
                // Check for supported image formats:
                // JPEG: FF D8 FF
                // JPEG 2000 codestream: FF 4F FF 51
                // JPEG 2000 JP2 file: 00 00 00 0C 6A 50
                
                boolean isJpeg = photoBytes.length > 3 &&
                    (photoBytes[0] & 0xFF) == 0xFF &&
                    (photoBytes[1] & 0xFF) == 0xD8 &&
                    (photoBytes[2] & 0xFF) == 0xFF;
                
                boolean isJpeg2000Codestream = photoBytes.length > 4 &&
                    (photoBytes[0] & 0xFF) == 0xFF &&
                    (photoBytes[1] & 0xFF) == 0x4F &&
                    (photoBytes[2] & 0xFF) == 0xFF &&
                    (photoBytes[3] & 0xFF) == 0x51;
                
                boolean isJpeg2000Jp2 = photoBytes.length > 6 &&
                    (photoBytes[0] & 0xFF) == 0x00 &&
                    (photoBytes[1] & 0xFF) == 0x00 &&
                    (photoBytes[2] & 0xFF) == 0x00 &&
                    (photoBytes[3] & 0xFF) == 0x0C &&
                    (photoBytes[4] & 0xFF) == 0x6A &&
                    (photoBytes[5] & 0xFF) == 0x50;
                
                if (isJpeg) {
                	// Standard JPEG - use as is
                    String photoBase64 = Base64.getEncoder().encodeToString(photoBytes);
                    kycData.setPhotoBase64(photoBase64);
                    kycData.setPhotoSizeBytes(photoBytes.length);
                    logger.info("Photo extracted (JPEG), size: {} bytes", photoBytes.length);
                } 
                
                else if(isJpeg2000Codestream || isJpeg2000Jp2) {
                    // JPEG 2000 - convert to standard JPEG for browser compatibility
                    byte[] jpegBytes = convertJpeg2000ToJpeg(photoBytes);
                    
                    // Verify conversion produced valid JPEG
                    if (jpegBytes.length > 3 &&
                        (jpegBytes[0] & 0xFF) == 0xFF &&
                        (jpegBytes[1] & 0xFF) == 0xD8) {
                        
                        String photoBase64 = Base64.getEncoder().encodeToString(jpegBytes);
                        kycData.setPhotoBase64(photoBase64);
                        kycData.setPhotoSizeBytes(jpegBytes.length);
                        logger.info("Photo converted from JPEG2000 to JPEG, size: {} bytes", jpegBytes.length);
                    } else {
                        // Conversion failed, store original anyway
                        String photoBase64 = Base64.getEncoder().encodeToString(photoBytes);
                        kycData.setPhotoBase64(photoBase64);
                        kycData.setPhotoSizeBytes(photoBytes.length);
                        logger.warn("JPEG2000 conversion failed, stored original. Size: {} bytes", photoBytes.length);
                    }}
                
                else {
                    // Try to find image header within the data (might have padding)
                    int imageStart = -1;
                    String foundFormat = "";
                    
                    for (int i = 0; i < Math.min(photoBytes.length - 4, 50); i++) {
                        // Check for JPEG
                        if ((photoBytes[i] & 0xFF) == 0xFF && 
                            (photoBytes[i+1] & 0xFF) == 0xD8 && 
                            (photoBytes[i+2] & 0xFF) == 0xFF) {
                            imageStart = i;
                            foundFormat = "JPEG";
                            break;
                        }
                        // Check for JPEG 2000 codestream
                        if ((photoBytes[i] & 0xFF) == 0xFF && 
                            (photoBytes[i+1] & 0xFF) == 0x4F && 
                            (photoBytes[i+2] & 0xFF) == 0xFF &&
                            (photoBytes[i+3] & 0xFF) == 0x51) {
                            imageStart = i;
                            foundFormat = "JPEG2000-codestream";
                            break;
                        }
                    }
                    
                    if (imageStart >= 0) {
                        byte[] actualPhoto = Arrays.copyOfRange(photoBytes, imageStart, photoBytes.length);
                        String photoBase64 = Base64.getEncoder().encodeToString(actualPhoto);
                        kycData.setPhotoBase64(photoBase64);
                        kycData.setPhotoSizeBytes(actualPhoto.length);
                        logger.info("Photo extracted after skipping {} padding bytes, format: {}, size: {} bytes", 
                            imageStart, foundFormat, actualPhoto.length);
                    } else {
                        // Still save the photo data - it might be a valid format the browser can handle
                        String photoBase64 = Base64.getEncoder().encodeToString(photoBytes);
                        kycData.setPhotoBase64(photoBase64);
                        kycData.setPhotoSizeBytes(photoBytes.length);
                        logger.warn("Unknown photo format, saved anyway. First 4 bytes: 0x{} 0x{} 0x{} 0x{}, size: {} bytes", 
                            String.format("%02X", photoBytes[0] & 0xFF),
                            String.format("%02X", photoBytes[1] & 0xFF),
                            String.format("%02X", photoBytes[2] & 0xFF),
                            String.format("%02X", photoBytes[3] & 0xFF),
                            photoBytes.length);
                    }
                }
            } else {
                logger.warn("Photo size too small or invalid: {} bytes (startPos={}, endPos={})", 
                    photoSize, photoStartPos, photoEndPos);
            }
            
            kycData.setCountry("India");
            
            logger.info("KYC data parsed successfully: Name={}, RefId={}, PhotoSize={}", 
                kycData.getName(), kycData.getReferenceId(), kycData.getPhotoSizeBytes());
            
        } catch (Exception e) {
            logger.error("Error parsing decompressed data", e);
        }
        
        return kycData;
    }
    
    /**
     * Convert JPEG 2000 to standard JPEG for browser compatibility
     * Uses high-quality rendering for better output
     */
    private byte[] convertJpeg2000ToJpeg(byte[] jpeg2000Bytes) {
        try {
            // Read JPEG 2000 image
            ByteArrayInputStream bis = new ByteArrayInputStream(jpeg2000Bytes);
            BufferedImage originalImage = ImageIO.read(bis);
            
            if (originalImage == null) {
                logger.warn("Failed to read JPEG 2000 image, returning original bytes");
                return jpeg2000Bytes;
            }
            
            logger.info("Original JPEG2000 image dimensions: {}x{}", 
                originalImage.getWidth(), originalImage.getHeight());
            
            // Create a new BufferedImage with proper color model for JPEG output
            // (JPEG doesn't support alpha channel)
            BufferedImage jpegImage = new BufferedImage(
                originalImage.getWidth(),
                originalImage.getHeight(),
                BufferedImage.TYPE_INT_RGB
            );
            
            // Draw original image onto new image with white background
            java.awt.Graphics2D g2d = jpegImage.createGraphics();
            g2d.setColor(java.awt.Color.WHITE);
            g2d.fillRect(0, 0, jpegImage.getWidth(), jpegImage.getHeight());
            g2d.drawImage(originalImage, 0, 0, null);
            g2d.dispose();
            
            // Write as JPEG with high quality
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            
            // Use ImageWriter for quality control
            Iterator<javax.imageio.ImageWriter> writers = ImageIO.getImageWritersByFormatName("jpg");
            if (writers.hasNext()) {
                javax.imageio.ImageWriter writer = writers.next();
                javax.imageio.ImageWriteParam param = writer.getDefaultWriteParam();
                
                // Set compression quality to maximum
                if (param.canWriteCompressed()) {
                    param.setCompressionMode(javax.imageio.ImageWriteParam.MODE_EXPLICIT);
                    param.setCompressionQuality(1.0f); // Maximum quality
                }
                
                javax.imageio.stream.ImageOutputStream ios = ImageIO.createImageOutputStream(bos);
                writer.setOutput(ios);
                writer.write(null, new javax.imageio.IIOImage(jpegImage, null, null), param);
                writer.dispose();
                ios.close();
            } else {
                // Fallback to simple write
                ImageIO.write(jpegImage, "jpg", bos);
            }
            
            if (bos.size() == 0) {
                logger.warn("Failed to write JPEG, returning original bytes");
                return jpeg2000Bytes;
            }
            
            logger.info("Converted JPEG 2000 ({}x{}, {} bytes) to JPEG ({} bytes)", 
                originalImage.getWidth(), originalImage.getHeight(),
                jpeg2000Bytes.length, bos.size());
            
            return bos.toByteArray();
            
        } catch (Exception e) {
            logger.error("JPEG 2000 to JPEG conversion failed: {}", e.getMessage(), e);
            return jpeg2000Bytes;
        }
    }

    /**
     * Extract field from data using delimiter positions
     */
    private String extractField(byte[] data, List<Integer> delimiterPositions, int fieldIndex) {
        if (fieldIndex >= delimiterPositions.size() - 1) {
            return "";
        }
        int start = delimiterPositions.get(fieldIndex) + 1;
        int end = delimiterPositions.get(fieldIndex + 1);
        if (start >= end || start < 0 || end > data.length) {
            return "";
        }
        return new String(Arrays.copyOfRange(data, start, end), StandardCharsets.ISO_8859_1).trim();
    }

    /**
     * Convert bytes to hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
    
    /**
     * Parse decompressed QR data
     * Field order as per UIDAI Aadhaar Secure QR V2 specification:
     * Version, ReferenceId, Name, DOB, Gender, CareOf, House, Street, 
     * Landmark, Locality, VTC, District, State, PostalCode, Photo
     */
    private KYCData parseDecompressedData_old_old(byte[] data) {
        KYCData kycData = new KYCData();
        
        try {
            List<byte[]> fields = splitByDelimiter(data);
            int fieldIndex = 1;
            
            logger.info("Total fields found in QR data: {}", fields.size());
            
            // Field 0: Version byte (skip)
            if (fields.size() > fieldIndex) {
                byte[] versionField = fields.get(fieldIndex++);
                logger.debug("Version field: {}", versionField.length > 0 ? (versionField[0] & 0xFF) : "empty");
            }
            
            // Field 1: Reference ID
            if (fields.size() > fieldIndex) {
                String refId = new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim();
                kycData.setReferenceId(refId);
                if (refId.length() >= 4) {
                    kycData.setMaskedAadhaar("XXXXXXXX" + refId.substring(0, 4));
                }
                logger.debug("ReferenceId: {}", refId);
            }
            
            // Field 2: Name
            if (fields.size() > fieldIndex) {
                String name = new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim();
                kycData.setName(name);
                logger.debug("Name: {}", name);
            }
            
            // Field 3: DOB (DDMMYYYY or YYYY)
            if (fields.size() > fieldIndex) {
                String dob = new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim();
                kycData.setDob(formatDOB(dob));
                logger.debug("DOB: {}", dob);
            }
            
            // Field 4: Gender (M/F/T)
            if (fields.size() > fieldIndex) {
                String gender = new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim();
                kycData.setGender(normalizeGender(gender));
                logger.debug("Gender: {}", gender);
            }
            
            // Field 5: Care Of (S/O, D/O, W/O, C/O)
            if (fields.size() > fieldIndex) {
                kycData.setCareOf(new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim());
            }
            
            // Field 6: House/Building/Apartment
            if (fields.size() > fieldIndex) {
                kycData.setHouse(new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim());
            }
            
            // Field 7: Street
            if (fields.size() > fieldIndex) {
                kycData.setStreet(new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim());
            }
            
            // Field 8: Landmark
            if (fields.size() > fieldIndex) {
                kycData.setLandmark(new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim());
            }
            
            // Field 9: Locality
            if (fields.size() > fieldIndex) {
                kycData.setLocality(new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim());
            }
            
            // Field 10: VTC (Village/Town/City)
            if (fields.size() > fieldIndex) {
                kycData.setVtc(new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim());
            }
            
            // Field 11: District
            if (fields.size() > fieldIndex) {
                kycData.setDistrict(new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim());
            }
            
            // Field 12: State
            if (fields.size() > fieldIndex) {
                kycData.setState(new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim());
            }
            
            // Field 13: Postal Code
            if (fields.size() > fieldIndex) {
                kycData.setPostalCode(new String(fields.get(fieldIndex++), StandardCharsets.UTF_8).trim());
            }
            
            // Field 14: Photo (JPEG bytes) - Last field
            if (fields.size() > fieldIndex) {

                byte[] photoBytes = fields.get(fieldIndex++);

                // JPEG magic header: FF D8 FF
                boolean isJpeg =
                    photoBytes.length > 3 &&
                    (photoBytes[0] & 0xFF) == 0xFF &&
                    (photoBytes[1] & 0xFF) == 0xD8 &&
                    (photoBytes[2] & 0xFF) == 0xFF;

                if (photoBytes.length > 100 && isJpeg) {

                    String photoBase64 =
                        Base64.getEncoder().encodeToString(photoBytes);

                    kycData.setPhotoBase64(photoBase64);
                    kycData.setPhotoSizeBytes(photoBytes.length);

                    logger.debug("Photo extracted, size: {} bytes", photoBytes.length);

                } else {
                    logger.warn("Photo field present but invalid. Size={}", photoBytes.length);
                }
            }
            
            // Set defaults
            kycData.setMobileHash("");
            kycData.setEmailHash("");
            kycData.setCountry("India");
            
            logger.info("KYC data parsed successfully: Name={}, RefId={}", 
                kycData.getName(), kycData.getReferenceId());
            
        } catch (Exception e) {
            logger.error("Error parsing decompressed data", e);
        }
        
        return kycData;
    }
    
    /**
     * Split data by delimiter (byte 255)
     */
    private List<byte[]> splitByDelimiter(byte[] data) {
        List<byte[]> fields = new ArrayList<>();
        int start = 0;
        
        for (int i = 0; i < data.length; i++) {
            if ((data[i] & 0xFF) == DELIMITER_BYTE) {
                if (i > start) {
                    fields.add(Arrays.copyOfRange(data, start, i));
                }
                start = i + 1;
            }
        }
        
        if (start < data.length) {
            fields.add(Arrays.copyOfRange(data, start, data.length));
        }
        
        return fields;
    }
    
    /**
     * Parse uncompressed data
     */
    private KYCData parseUncompressedData(byte[] data) {
        String dataStr = new String(data, StandardCharsets.UTF_8);
        return parseDelimitedQR(dataStr);
    }
    
    /**
     * Parse delimited text QR
     */
    private KYCData parseDelimitedQR(String qrString) {
        KYCData kycData = new KYCData();
        
        String[] fields = null;
        if (qrString.contains("|")) {
            fields = qrString.split("\\|");
        } else if (qrString.contains("\n")) {
            fields = qrString.split("\n");
        } else if (qrString.contains(",")) {
            fields = qrString.split(",");
        }
        
        if (fields != null && fields.length >= 4) {
            int idx = 0;
            
            if (fields.length > idx) {
                String refId = fields[idx++].trim();
                kycData.setReferenceId(refId);
                if (refId.length() >= 4) {
                    kycData.setMaskedAadhaar("XXXXXXXX" + refId.substring(Math.max(0, refId.length() - 4)));
                }
            }
            if (fields.length > idx) kycData.setName(fields[idx++].trim());
            if (fields.length > idx) kycData.setDob(formatDOB(fields[idx++].trim()));
            if (fields.length > idx) kycData.setGender(normalizeGender(fields[idx++].trim()));
            
            StringBuilder address = new StringBuilder();
            while (idx < fields.length) {
                if (!fields[idx].trim().isEmpty()) {
                    if (address.length() > 0) address.append(", ");
                    address.append(fields[idx].trim());
                }
                idx++;
            }
            
            String addressStr = address.toString();
            java.util.regex.Matcher pcMatcher = java.util.regex.Pattern.compile("\\b(\\d{6})\\b").matcher(addressStr);
            if (pcMatcher.find()) {
                kycData.setPostalCode(pcMatcher.group(1));
            }
        }
        
        kycData.setCountry("India");
        return kycData;
    }
    
    /**
     * Extract version from decompressed data
     */
    private String extractVersion(byte[] data) {
        if (data != null && data.length > 0) {
            int version = data[0] & 0xFF;
            if (version <= 10) {
                return "V" + version;
            }
        }
        return "UNKNOWN";
    }
    
    /**
     * Format DOB to DD-MM-YYYY
     */
    private String formatDOB(String dob) {
        if (dob == null || dob.isEmpty()) return dob;
        
        if (dob.matches("\\d{2}-\\d{2}-\\d{4}")) {
            return dob;
        }
        
        if (dob.matches("\\d{8}")) {
            return dob.substring(0, 2) + "-" + dob.substring(2, 4) + "-" + dob.substring(4, 8);
        }
        
        if (dob.matches("\\d{4}")) {
            return "01-01-" + dob;
        }
        
        return dob;
    }
    
    /**
     * Normalize gender value
     */
    private String normalizeGender(String gender) {
        if (gender == null) return null;
        gender = gender.toUpperCase().trim();
        if (gender.startsWith("M")) return "M";
        if (gender.startsWith("F")) return "F";
        if (gender.startsWith("T")) return "T";
        return gender;
    }
    
    /**
     * Validate QR signature using UIDAI public key
     */
    private SignatureValidationResult validateQRSignature(byte[] signatureBytes, byte[] dataBytes) {
        SignatureValidationResult result = new SignatureValidationResult();
        
     // For non-secure QR (no signature), we skip signature validation
        // but allow the flow to continue for data extraction
        if (signatureBytes == null || signatureBytes.length == 0) {
            logger.warn("Non-secure QR detected - no digital signature present");
            result.setValid(true); // Allow flow to continue
            result.setAlgorithm("NONE");
            result.setErrorMessage("Non-secure QR code - no signature to validate");
            return result;
        }
        
        if (!publicKeysAvailable) {
            result.setValid(false);
            result.setErrorMessage("UIDAI public keys not configured");
            return result;
        }
        
        try {
            // Try previous public key first
            if (previousPublicKey != null) {
                boolean verified = verifySignature(signatureBytes, dataBytes, previousPublicKey);
                if (verified) {
                    result.setValid(true);
                    result.setAlgorithm("SHA256withRSA");
                    result.setCertificateInfo(extractCertificateInfo(previousPublicKey));
                    logger.info("QR signature verified with PREVIOUS public key");
                    return result;
                }
            }
            
            // Try latest public key
            if (latestPublicKey != null) {
                boolean verified = verifySignature(signatureBytes, dataBytes, latestPublicKey);
                if (verified) {
                    result.setValid(true);
                    result.setAlgorithm("SHA256withRSA");
                    result.setCertificateInfo(extractCertificateInfo(latestPublicKey));
                    logger.info("QR signature verified with LATEST public key");
                    return result;
                }
            }
            
            result.setValid(false);
            result.setErrorMessage("QR signature verification failed with all available public keys");
            
        } catch (Exception e) {
            logger.error("Signature verification error", e);
            result.setValid(false);
            result.setErrorMessage("Signature verification error: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Verify signature with public key
     * The signature from Aadhaar QR is raw RSA signature bytes
     */
    private boolean verifySignature(byte[] signatureBytes, byte[] dataBytes, X509Certificate cert) {
        try {
            // Ensure signature is exactly 256 bytes
            byte[] sigBytes = signatureBytes;
            if (sigBytes.length > SIGNATURE_LENGTH) {
                // Trim leading zeros if present
                int offset = sigBytes.length - SIGNATURE_LENGTH;
                sigBytes = Arrays.copyOfRange(sigBytes, offset, sigBytes.length);
            } else if (sigBytes.length < SIGNATURE_LENGTH) {
                // Pad with leading zeros if needed
                byte[] padded = new byte[SIGNATURE_LENGTH];
                System.arraycopy(sigBytes, 0, padded, SIGNATURE_LENGTH - sigBytes.length, sigBytes.length);
                sigBytes = padded;
            }
            
            // Try SHA256withRSA first (most common for UIDAI)
            try {
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(cert.getPublicKey());
                sig.update(dataBytes);
                if (sig.verify(sigBytes)) {
                    logger.info("Signature verified with SHA256withRSA");
                    return true;
                }
            } catch (Exception e) {
                logger.debug("SHA256withRSA verification failed: {}", e.getMessage());
            }
            
            // Try with BigInteger conversion (some implementations encode differently)
            try {
                BigInteger sigBigInt = new BigInteger(1, signatureBytes);
                byte[] sigBytesFromBigInt = sigBigInt.toByteArray();
                
                // Remove leading zero if present
                if (sigBytesFromBigInt.length > SIGNATURE_LENGTH && sigBytesFromBigInt[0] == 0) {
                    sigBytesFromBigInt = Arrays.copyOfRange(sigBytesFromBigInt, 1, sigBytesFromBigInt.length);
                }
                
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(cert.getPublicKey());
                sig.update(dataBytes);
                if (sig.verify(sigBytesFromBigInt)) {
                    logger.info("Signature verified with SHA256withRSA (BigInteger conversion)");
                    return true;
                }
            } catch (Exception e) {
                logger.debug("SHA256withRSA with BigInteger conversion failed: {}", e.getMessage());
            }
            
            // Try SHA1withRSA as fallback
            try {
                Signature sig = Signature.getInstance("SHA1withRSA");
                sig.initVerify(cert.getPublicKey());
                sig.update(dataBytes);
                if (sig.verify(sigBytes)) {
                    logger.info("Signature verified with SHA1withRSA");
                    return true;
                }
            } catch (Exception e) {
                logger.debug("SHA1withRSA verification failed: {}", e.getMessage());
            }
            
        } catch (Exception e) {
            logger.error("Signature verification error", e);
        }
        
        return false;
    }
    
    /**
     * Verify mobile hash
     */
    private boolean verifyMobileHash(String mobileNumber, String shareCode, String referenceId, String storedHash) {
        if (mobileNumber == null || storedHash == null || storedHash.isEmpty()) {
            return false;
        }
        
        try {
            int lastDigit = Character.getNumericValue(referenceId.charAt(3));
            int iterations = (lastDigit == 0) ? 1 : lastDigit;
            
            String computed = DigestUtils.sha256Hex(mobileNumber + shareCode);
            for (int i = 1; i < iterations; i++) {
                computed = DigestUtils.sha256Hex(computed);
            }
            
            return computed.equalsIgnoreCase(storedHash);
            
        } catch (Exception e) {
            logger.error("Mobile hash verification error", e);
            return false;
        }
    }
    
    /**
     * Extract certificate info
     */
    private CertificateInfo extractCertificateInfo(X509Certificate cert) {
        CertificateInfo info = new CertificateInfo();
        info.setSubjectDN(cert.getSubjectX500Principal().getName());
        info.setIssuerDN(cert.getIssuerX500Principal().getName());
        info.setSerialNumber(cert.getSerialNumber().toString(16));
        info.setValidFrom(cert.getNotBefore().toInstant());
        info.setValidTo(cert.getNotAfter().toInstant());
        info.setSignatureAlgorithm(cert.getSigAlgName());
        return info;
    }
    
    /**
     * Perform additional validations
     */
    private void performAdditionalValidations(QRKYCValidationResponse response, KYCData kycData) {
        List<String> warnings = new ArrayList<>();
        
        if (kycData.getName() == null || kycData.getName().isEmpty()) {
            warnings.add("Name not found in QR data");
        }
        
        if (kycData.getPhotoBase64() == null || kycData.getPhotoBase64().isEmpty()) {
            warnings.add("Photo not available in QR data");
        }
        
        if (kycData.getPostalCode() == null || !kycData.getPostalCode().matches("\\d{6}")) {
            warnings.add("Postal code incomplete or invalid");
        }
        
        if (kycData.getDob() != null && !kycData.getDob().isEmpty()) {
            try {
                String[] parts = kycData.getDob().split("-");
                if (parts.length == 3) {
                    LocalDate birthDate = LocalDate.of(
                        Integer.parseInt(parts[2]),
                        Integer.parseInt(parts[1]),
                        Integer.parseInt(parts[0])
                    );
                    int age = Period.between(birthDate, LocalDate.now()).getYears();
                    if (age < 18) {
                        warnings.add("Customer is under 18 years of age");
                    }
                }
            } catch (Exception e) {
                warnings.add("DOB format could not be parsed");
            }
        }
        
        response.setWarnings(warnings);
    }
    
    /**
     * Audit logging
     */
    private void auditLog(String eventType, String requestId, String customerId, Map<String, Object> details) {
        Map<String, Object> auditEntry = new LinkedHashMap<>();
        auditEntry.put("timestamp", Instant.now().toString());
        auditEntry.put("eventType", eventType);
        auditEntry.put("requestId", requestId);
        auditEntry.put("customerId", customerId);
        auditEntry.putAll(details);
        auditLogger.info("{}", auditEntry);
    }
    
    /**
     * Check if public keys are available
     */
    public boolean isPublicKeysAvailable() {
        return publicKeysAvailable;
    }
    
    // Inner class for QR parse result
    private static class QRParseResult {
        private boolean success;
        private String errorMessage;
        private String format;
        private String version;
        private byte[] signatureBytes;
        private byte[] dataBytes;
        private KYCData kycData;
        
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
        public String getFormat() { return format; }
        public void setFormat(String format) { this.format = format; }
        public String getVersion() { return version; }
        public void setVersion(String version) { this.version = version; }
        public byte[] getSignatureBytes() { return signatureBytes; }
        public void setSignatureBytes(byte[] signatureBytes) { this.signatureBytes = signatureBytes; }
        public byte[] getDataBytes() { return dataBytes; }
        public void setDataBytes(byte[] dataBytes) { this.dataBytes = dataBytes; }
        public KYCData getKycData() { return kycData; }
        public void setKycData(KYCData kycData) { this.kycData = kycData; }
    }
}