package com.sberbank.kyc.controller;

import com.sberbank.kyc.*;
import com.sberbank.kyc.model.KYCApiResponse;
import com.sberbank.kyc.model.KYCData;
import com.sberbank.kyc.model.KYCValidationResponse;
import com.sberbank.kyc.model.ValidationResult;
import com.sberbank.kyc.service.OfflineKYCService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.validation.constraints.*;
import java.util.UUID;

/**
 * REST Controller for Offline Aadhaar KYC Validation
 * 
 * Endpoints:
 * - POST /api/v1/kyc/validate - Validate offline KYC XML
 * - GET /api/v1/kyc/status/{requestId} - Check validation status
 * - GET /api/v1/kyc/health - Health check
 */
@RestController
@RequestMapping("/api/v1/kyc")
@Tag(name = "Offline KYC", description = "Offline Aadhaar KYC Validation APIs")
public class OfflineKYCController {
    
    private static final Logger logger = LoggerFactory.getLogger(OfflineKYCController.class);
    
    @Autowired
    private OfflineKYCService kycService;
    
    /**
     * Validate offline Aadhaar KYC XML file
     * 
     * @param zipFile Offline KYC XML file
     * @param shareCode 4-digit share code
     * @param customerId Optional customer ID
     * @return Validation response
     */
    @PostMapping(value = "/validate", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Validate offline Aadhaar KYC ZIP", 
               description = "Extracts XML from password-protected ZIP (using shareCode), validates signature, certificate chain, and extracts KYC data")
    public ResponseEntity<KYCApiResponse> validateKYC(
            @RequestParam("file") MultipartFile zipFile,
            @RequestParam("shareCode") @Pattern(regexp = "\\d{4}") String shareCode,
            @RequestParam(required = false) String mobileNumber,
            @RequestParam(value = "customerId", required = false) String customerId,
            @RequestHeader(value = "X-Request-ID", required = false) String requestId) {
        
        // Generate request ID if not provided
        if (requestId == null || requestId.isEmpty()) {
            requestId = UUID.randomUUID().toString();
        }
        
        logger.info("KYC validation request received. RequestId: {}, FileName: {}", 
            requestId, zipFile.getOriginalFilename());
        
        try {
            // Perform validation
            KYCValidationResponse validationResult = kycService.validateKYC(
            		zipFile, shareCode, mobileNumber, customerId, requestId);
            
            // Build API response
            KYCApiResponse response = buildApiResponse(validationResult, requestId);
            
            // Return appropriate HTTP status
            HttpStatus status = validationResult.getResult() == ValidationResult.VALID 
                ? HttpStatus.OK 
                : HttpStatus.BAD_REQUEST;
            
            return ResponseEntity.status(status)
                .header("X-Request-ID", requestId)
                .body(response);
                
        } catch (Exception e) {
            logger.error("KYC validation error. RequestId: {}", requestId, e);
            
            KYCApiResponse errorResponse = new KYCApiResponse();
            errorResponse.setSuccess(false);
            errorResponse.setRequestId(requestId);
            errorResponse.setErrorCode("INTERNAL_ERROR");
            errorResponse.setErrorMessage("Internal server error during validation");
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .header("X-Request-ID", requestId)
                .body(errorResponse);
        }
    }
    
    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    @Operation(summary = "Health check", description = "Returns service health status")
    public ResponseEntity<HealthResponse> healthCheck() {
        HealthResponse health = new HealthResponse();
        health.setStatus("UP");
        health.setService("offline-kyc-validation");
        health.setTimestamp(java.time.Instant.now().toString());
        
        return ResponseEntity.ok(health);
    }
    
    private KYCApiResponse buildApiResponse(KYCValidationResponse validationResult, 
            String requestId) {
        
        KYCApiResponse response = new KYCApiResponse();
        response.setRequestId(requestId);
        response.setSuccess(validationResult.getResult() == ValidationResult.VALID);
        response.setValidationResult(validationResult.getResult().name());
        
        if (validationResult.getResult() == ValidationResult.VALID) {
            // Include KYC data in response
            KYCData kycData = validationResult.getKycData();
            if (kycData != null) {
                KYCApiResponse.KYCDataDTO dataDTO = new KYCApiResponse.KYCDataDTO();
                dataDTO.setReferenceId(kycData.getReferenceId());
                dataDTO.setMaskedAadhaar(kycData.getMaskedAadhaar());
                dataDTO.setName(kycData.getName());
                dataDTO.setDob(kycData.getDob());
                dataDTO.setGender(kycData.getGender());
                
                // Address
                KYCApiResponse.AddressDTO address = new KYCApiResponse.AddressDTO();
                address.setCareOf(kycData.getCareOf());
                address.setHouse(kycData.getHouse());
                address.setStreet(kycData.getStreet());
                address.setLandmark(kycData.getLandmark());
                address.setLocality(kycData.getLocality());
                address.setVtc(kycData.getVtc());
                address.setDistrict(kycData.getDistrict());
                address.setState(kycData.getState());
                address.setPostalCode(kycData.getPostalCode());
                address.setCountry(kycData.getCountry());
                dataDTO.setAddress(address);
                
                // Photo availability
                dataDTO.setPhotoAvailable(kycData.getPhotoBase64() != null);
                dataDTO.setPhotoBase64(kycData.getPhotoBase64());
                
             // Mobile verification
                dataDTO.setMobileVerified(kycData.isMobileVerified());
                if (kycData.isMobileVerified()) {
                    dataDTO.setVerifiedMobileNumber(kycData.getVerifiedMobileNumber());
                }
                
                response.setKycData(dataDTO);
            }
            
            // Validation details
            response.setSignatureValid(validationResult.isSignatureValid());
            response.setCertificateValid(validationResult.isCertificateChainValid());
            response.setShareCodeValid(validationResult.isShareCodeValid());
            
        } else {
            response.setErrorCode(validationResult.getResult().name());
            response.setErrorMessage(validationResult.getErrorMessage());
        }
        
        return response;
    }
}

class HealthResponse {
    private String status;
    private String service;
    private String timestamp;
    
    public void setStatus(String s) { this.status = s; }
    public String getStatus() { return status; }
    public void setService(String s) { this.service = s; }
    public void setTimestamp(String t) { this.timestamp = t; }
}
