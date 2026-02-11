package com.sberbank.kyc.controller;

import com.sberbank.kyc.model.*;
import com.sberbank.kyc.service.QRKYCValidatorService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.constraints.Pattern;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * REST Controller for Aadhaar QR Code KYC Validation
 * 
 * This controller handles validation of Aadhaar Secure QR codes that are
 * scanned by the UI and sent as raw decoded data.
 * 
 * @author Sberbank India - Enterprise Architecture
 * @version 1.0
 */
@RestController
@RequestMapping("/api/v1/kyc")
@Tag(name = "QR KYC Validation", description = "Aadhaar QR Code validation APIs")
public class QRKYCController {
    
    private static final Logger logger = LoggerFactory.getLogger(QRKYCController.class);
    
    @Autowired
    private QRKYCValidatorService qrKycService;
    
    /**
     * Validate Aadhaar QR Code
     * 
     * Receives the raw decoded QR data from UI (after scanning) and validates it.
     * 
     * @param request QR validation request containing raw QR data
     * @param requestId Optional request ID for tracking
     * @return KYCApiResponse with validation results
     */
    @PostMapping(value = "/qr/validate", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        summary = "Validate Aadhaar QR Code",
        description = "Validates the raw decoded Aadhaar QR code data. The UI scans the QR code and sends the decoded data to this endpoint for validation."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Validation successful",
            content = @Content(schema = @Schema(implementation = KYCApiResponse.class))),
        @ApiResponse(responseCode = "400", description = "Validation failed",
            content = @Content(schema = @Schema(implementation = KYCApiResponse.class))),
        @ApiResponse(responseCode = "500", description = "Internal server error",
            content = @Content(schema = @Schema(implementation = KYCApiResponse.class)))
    })
    public ResponseEntity<KYCApiResponse> validateQRKYC(
            @RequestBody QRKYCValidationRequest request,
            @RequestHeader(value = "X-Request-ID", required = false) String requestId) {
        
        // Generate request ID if not provided
        if (requestId == null || requestId.isEmpty()) {
            requestId = UUID.randomUUID().toString();
        }
        
        logger.info("QR KYC validation request received. RequestId: {}, DataLength: {}", 
            requestId, request.getRawQRData() != null ? request.getRawQRData().length() : 0);
        
        try {
            // Validate the QR code
            QRKYCValidationResponse validationResult = qrKycService.validateQRCode(
                request.getRawQRData(),
                request.getShareCode(),
                request.getMobileNumber(),
                request.getCustomerId(),
                requestId
            );
            
            // Build API response
            KYCApiResponse response = buildApiResponse(validationResult, requestId);
            
            // Determine HTTP status
            HttpStatus status = validationResult.getResult() == ValidationResult.VALID 
                ? HttpStatus.OK 
                : HttpStatus.BAD_REQUEST;
            
            return ResponseEntity
                .status(status)
                .header("X-Request-ID", requestId)
                .body(response);
            
        } catch (Exception e) {
            logger.error("QR KYC validation error. RequestId: {}", requestId, e);
            
            KYCApiResponse errorResponse = new KYCApiResponse();
            errorResponse.setSuccess(false);
            errorResponse.setRequestId(requestId);
            errorResponse.setErrorCode("INTERNAL_ERROR");
            errorResponse.setErrorMessage("QR validation error");
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .header("X-Request-ID", requestId)
                .body(errorResponse);
        }
    }
    
    /**
     * Health check for QR validation service
     */
    @GetMapping("/qr/health")
    @Operation(summary = "Health check for QR validation service")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("status", "UP");
        health.put("service", "QR KYC Validation");
        health.put("timestamp", Instant.now().toString());
        health.put("publicKeysLoaded", qrKycService.isPublicKeysAvailable());
        
        return ResponseEntity.ok(health);
    }
    
    /**
     * Build API response from validation result
     */
    private KYCApiResponse buildApiResponse(QRKYCValidationResponse validationResult, String requestId) {
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

/**
 * Request model for QR KYC Validation
 */
class QRKYCValidationRequest {
    
    @Schema(description = "Raw decoded QR data from scanner (Base64 or raw string)", required = true)
    private String rawQRData;
    
    @Schema(description = "4-digit share code", required = true, example = "1234")
    @Pattern(regexp = "\\d{4}", message = "Share code must be exactly 4 digits")
    private String shareCode;
    
    @Schema(description = "10-digit mobile number for verification", example = "9876543210")
    private String mobileNumber;
    
    @Schema(description = "Customer ID for audit purposes")
    private String customerId;
    
    // Getters and Setters
    public String getRawQRData() { return rawQRData; }
    public void setRawQRData(String rawQRData) { this.rawQRData = rawQRData; }
    
    public String getShareCode() { return shareCode; }
    public void setShareCode(String shareCode) { this.shareCode = shareCode; }
    
    public String getMobileNumber() { return mobileNumber; }
    public void setMobileNumber(String mobileNumber) { this.mobileNumber = mobileNumber; }
    
    public String getCustomerId() { return customerId; }
    public void setCustomerId(String customerId) { this.customerId = customerId; }
}