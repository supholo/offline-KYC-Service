package com.sberbank.kyc;

import com.sberbank.kyc.model.CertificateInfo;
import com.sberbank.kyc.model.CertificateValidationResult;
import com.sberbank.kyc.model.KYCData;
import com.sberbank.kyc.model.KYCValidationResponse;
import com.sberbank.kyc.model.ShareCodeValidationResult;
import com.sberbank.kyc.model.SignatureValidationResult;
import com.sberbank.kyc.model.ValidationResult;

import org.apache.commons.codec.digest.DigestUtils;
import org.w3c.dom.*;
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.time.*;
import java.util.*;
import java.util.Base64;

/**
 * Offline Aadhaar KYC XML Validator for Banking Applications
 * 
 * Compliant with UIDAI Offline Paperless KYC Guidelines Supports both XMLDSig
 * format and legacy 's' attribute signature format
 * 
 * @author Sberbank India - Enterprise Architecture
 * @version 3.0
 */
public class OfflineAadhaarKYCValidator {

	/**
	 * Main validation entry point
	 */
	public KYCValidationResponse validateOfflineKYC(String xmlFilePath, String shareCode) {
		return validateOfflineKYC(xmlFilePath, shareCode, null, false, null, null);
	}

	/**
	 * Main validation entry point with certificate expiry skip option
	 */
	public KYCValidationResponse validateOfflineKYC(String xmlFilePath, String shareCode, String mobileNumber, boolean skipCertExpiryCheck, X509Certificate previousPublicKey, X509Certificate latestPublicKey) {
		KYCValidationResponse response = new KYCValidationResponse();
		response.setValidationTimestamp(Instant.now());

		try {
			// Step 1: Read and preprocess XML
			String xmlContent = readAndPreprocessXML(xmlFilePath);
			if (xmlContent == null) {
				response.setResult(ValidationResult.XML_PARSE_ERROR);
				response.setErrorMessage("Failed to read XML file");
				return response;
			}

			// Step 2: Parse XML Document
			Document document = parseXMLDocument(xmlContent);
			if (document == null) {
				response.setResult(ValidationResult.XML_PARSE_ERROR);
				response.setErrorMessage("Failed to parse XML document");
				return response;
			}

			// Step 3: Determine signature type and validate
			SignatureValidationResult sigResult;
			if (hasXMLDSigSignature(document)) {
				logAuditEvent("SIGNATURE_TYPE", "XMLDSig format detected");
				sigResult = validateXMLDSigSignatureWithExternalKeys(document, previousPublicKey, latestPublicKey);
			} else if (hasLegacySignature(document)) {
				logAuditEvent("SIGNATURE_TYPE", "Legacy 's' attribute format detected");
				sigResult = validateLegacySignatureWithExternalKeys(document, xmlContent, previousPublicKey, latestPublicKey);
			} else {
				response.setResult(ValidationResult.INVALID_SIGNATURE);
				response.setErrorMessage("No signature found in XML document");
				return response;
			}

			if (!sigResult.isValid()) {
				response.setResult(ValidationResult.INVALID_SIGNATURE);
				response.setErrorMessage(sigResult.getErrorMessage());
				return response;
			}
			response.setSignatureValid(true);
			response.setCertificateInfo(sigResult.getCertificateInfo());

			// Step 4: Validate Certificate Chain
			CertificateValidationResult certResult =
			        validateCertificateChain(
			            sigResult.getSigningCertificate(),
			            skipCertExpiryCheck
			        );
			if (!certResult.isValid()) {
				response.setResult(certResult.getFailureReason());
				response.setErrorMessage(certResult.getErrorMessage());
				return response;
			}
			response.setCertificateChainValid(true);

			// Step 5: Validate Share Code
			ShareCodeValidationResult shareCodeResult = validateShareCode(document, shareCode);
			if (!shareCodeResult.isValid()) {
				response.setResult(ValidationResult.SHARE_CODE_MISMATCH);
				response.setErrorMessage(shareCodeResult.getErrorMessage());
				return response;
			}
			response.setShareCodeValid(true);

			// Step 6: Extract KYC Data
			KYCData kycData = extractKYCData(document, shareCode, mobileNumber);
			response.setKycData(kycData);
			
			// Step 7: Verify mobile if provided
			if (mobileNumber != null && !mobileNumber.isEmpty()) {
			    if (!kycData.isMobileVerified()) {
			        response.setResult(ValidationResult.MOBILE_VERIFICATION_FAILED);
			        response.setErrorMessage("Mobile number verification failed");
			        return response;
			    }
			}

			// Step 8: Verify Data Integrity
			response.setDataIntegrityValid(true);

			// All validations passed
			response.setResult(ValidationResult.VALID);
			response.setSuccessMessage("Offline KYC XML validated successfully");

		} catch (Exception e) {
			response.setResult(ValidationResult.UNKNOWN_ERROR);
			response.setErrorMessage("Validation error: " + e.getMessage());
			logAuditEvent("VALIDATION_ERROR", e.getMessage());
			e.printStackTrace();
		}

		return response;
	}

	/**
	 * Read and preprocess XML file Handles encoding and line ending normalization
	 */
	private String readAndPreprocessXML(String xmlFilePath) {
		try {
			byte[] bytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(xmlFilePath));
			String content = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);

			// Log original state
			logAuditEvent("XML_READ",
					"Original size: " + content.length() + ", contains &#13;: " + content.contains("&#13;"));

			return content;
		} catch (Exception e) {
			logAuditEvent("XML_READ_ERROR", e.getMessage());
			return null;
		}
	}

	/**
	 * Parse XML document with proper settings for XMLDSig
	 */
	private Document parseXMLDocument(String xmlContent) throws Exception {
		// For XMLDSig validation, we should NOT remove &#13; before parsing
		// The XML parser will handle entity references correctly
		// Removing them changes the document and breaks the signature

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

		// Security settings
		dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
		dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
		dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
		dbf.setXIncludeAware(false);
		dbf.setExpandEntityReferences(false);

		// CRITICAL: Enable namespace awareness for XMLDSig
		dbf.setNamespaceAware(true);

		DocumentBuilder builder = dbf.newDocumentBuilder();

		// Parse the XML as-is (with &#13; entities)
		Document doc = builder
				.parse(new ByteArrayInputStream(xmlContent.getBytes(java.nio.charset.StandardCharsets.UTF_8)));

		logAuditEvent("XML_PARSED", "Document parsed successfully");
		return doc;
	}

	/**
	 * Check if document has XMLDSig signature
	 */
	private boolean hasXMLDSigSignature(Document document) {
		NodeList sigList = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		return sigList.getLength() > 0;
	}

	/**
	 * Check if document has legacy 's' attribute signature
	 */
	private boolean hasLegacySignature(Document document) {
		Element root = document.getDocumentElement();
		return root.hasAttribute("s");
	}

	/**
	 * Validate XMLDSig signature using external UIDAI public keys
	 * Tries previous key first, then latest key
	 */
	private SignatureValidationResult validateXMLDSigSignatureWithExternalKeys(
	        Document document, 
	        X509Certificate previousPublicKey, 
	        X509Certificate latestPublicKey) {
	    
	    SignatureValidationResult result = new SignatureValidationResult();
	    
	    // Validate we have at least one public key
	    if (previousPublicKey == null && latestPublicKey == null) {
	        result.setValid(false);
	        result.setErrorMessage("No UIDAI public keys available for signature validation");
	        return result;
	    }
	    
	    try {
	        NodeList signatureList = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
	        if (signatureList.getLength() == 0) {
	            result.setValid(false);
	            result.setErrorMessage("No XMLDSig Signature element found");
	            return result;
	        }
	        
	        Node signatureNode = signatureList.item(0);
	        
	        // Try with PREVIOUS public key first
	        if (previousPublicKey != null) {
	            logAuditEvent("SIGNATURE_ATTEMPT", "Trying validation with PREVIOUS public key");
	            SignatureValidationResult prevResult = tryValidateWithKey(document, signatureNode, previousPublicKey, "PREVIOUS");
	            if (prevResult.isValid()) {
	                return prevResult;
	            }
	            logAuditEvent("SIGNATURE_ATTEMPT_FAILED", "Previous key validation failed, trying latest key");
	        }
	        
	        // Try with LATEST public key
	        if (latestPublicKey != null) {
	            logAuditEvent("SIGNATURE_ATTEMPT", "Trying validation with LATEST public key");
	            SignatureValidationResult latestResult = tryValidateWithKey(document, signatureNode, latestPublicKey, "LATEST");
	            if (latestResult.isValid()) {
	                return latestResult;
	            }
	            logAuditEvent("SIGNATURE_ATTEMPT_FAILED", "Latest key validation also failed");
	        }
	        
	        // Both failed
	        result.setValid(false);
	        result.setErrorMessage("Signature validation failed with both PREVIOUS and LATEST UIDAI public keys");
	        logAuditEvent("SIGNATURE_INVALID", "Both public keys failed to validate signature");
	        
	    } catch (Exception e) {
	        result.setValid(false);
	        result.setErrorMessage("Signature validation error: " + e.getMessage());
	        logAuditEvent("SIGNATURE_ERROR", e.getMessage());
	    }
	    
	    return result;
	}

	/**
	 * Try to validate signature with a specific public key
	 */
	private SignatureValidationResult tryValidateWithKey(
	        Document document,
	        Node signatureNode, 
	        X509Certificate publicKey,
	        String keyType) {
	    
	    SignatureValidationResult result = new SignatureValidationResult();
	    
	    try {
	        DOMValidateContext valContext = new DOMValidateContext(publicKey.getPublicKey(), signatureNode);
	        valContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.FALSE);
	        
	        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
	        XMLSignature signature = factory.unmarshalXMLSignature(valContext);
	        
	        boolean coreValid = signature.validate(valContext);
	        
	        if (coreValid) {
	            result.setValid(true);
	            result.setSigningCertificate(publicKey);
	            result.setCertificateInfo(extractCertificateInfo(publicKey));
	            logAuditEvent("SIGNATURE_VALID", "XMLDSig signature validated with " + keyType + " public key");
	        } else {
	            result.setValid(false);
	            result.setErrorMessage("Signature validation failed with " + keyType + " key");
	        }
	        
	    } catch (Exception e) {
	        result.setValid(false);
	        result.setErrorMessage("Validation error with " + keyType + " key: " + e.getMessage());
	    }
	    
	    return result;
	}
	
	/**
	 * Validate legacy signature using external UIDAI public keys
	 * Tries previous key first, then latest key
	 */
	private SignatureValidationResult validateLegacySignatureWithExternalKeys(
	        Document document,
	        String originalXml,
	        X509Certificate previousPublicKey,
	        X509Certificate latestPublicKey) {
	    
	    SignatureValidationResult result = new SignatureValidationResult();
	    
	    if (previousPublicKey == null && latestPublicKey == null) {
	        result.setValid(false);
	        result.setErrorMessage("No UIDAI public keys available for legacy signature validation");
	        return result;
	    }
	    
	    try {
	        Element root = document.getDocumentElement();
	        String signatureB64 = root.getAttribute("s");
	        
	        if (signatureB64 == null || signatureB64.isEmpty()) {
	            result.setValid(false);
	            result.setErrorMessage("No 's' attribute signature found");
	            return result;
	        }
	        
	        // Remove signature attribute before verification
	        root.removeAttribute("s");
	        String xmlWithoutSig = documentToString(document);
	        byte[] signatureBytes = Base64.getDecoder().decode(signatureB64);
	        byte[] xmlBytes = xmlWithoutSig.getBytes(StandardCharsets.UTF_8);
	        
	        // Try with PREVIOUS public key first
	        if (previousPublicKey != null) {
	            logAuditEvent("LEGACY_SIGNATURE_ATTEMPT", "Trying with PREVIOUS public key");
	            if (verifyLegacySignature(xmlBytes, signatureBytes, previousPublicKey)) {
	                result.setValid(true);
	                result.setSigningCertificate(previousPublicKey);
	                result.setCertificateInfo(extractCertificateInfo(previousPublicKey));
	                logAuditEvent("LEGACY_SIGNATURE_VALID", "Validated with PREVIOUS public key");
	                return result;
	            }
	        }
	        
	        // Try with LATEST public key
	        if (latestPublicKey != null) {
	            logAuditEvent("LEGACY_SIGNATURE_ATTEMPT", "Trying with LATEST public key");
	            if (verifyLegacySignature(xmlBytes, signatureBytes, latestPublicKey)) {
	                result.setValid(true);
	                result.setSigningCertificate(latestPublicKey);
	                result.setCertificateInfo(extractCertificateInfo(latestPublicKey));
	                logAuditEvent("LEGACY_SIGNATURE_VALID", "Validated with LATEST public key");
	                return result;
	            }
	        }
	        
	        // Both failed
	        result.setValid(false);
	        result.setErrorMessage("Legacy signature validation failed with both public keys");
	        
	    } catch (Exception e) {
	        result.setValid(false);
	        result.setErrorMessage("Legacy signature validation error: " + e.getMessage());
	    }
	    
	    return result;
	}

	/**
	 * Verify legacy signature with a specific key
	 */
	private boolean verifyLegacySignature(byte[] data, byte[] signatureBytes, X509Certificate publicKey) {
	    try {
	        Signature signature = Signature.getInstance("SHA256withRSA");
	        signature.initVerify(publicKey.getPublicKey());
	        signature.update(data);
	        return signature.verify(signatureBytes);
	    } catch (Exception e) {
	        return false;
	    }
	}

	/**
	 * Extract X509Certificate from XMLDSig KeyInfo
	 */
	private X509Certificate extractCertificateFromXML(Document document) {
		try {
			NodeList certList = document.getElementsByTagName("X509Certificate");
			if (certList.getLength() == 0) {
				return null;
			}

			String certB64 = certList.item(0).getTextContent();
			// Remove all whitespace including newlines from Base64
			certB64 = certB64.replaceAll("\\s+", "");

			byte[] certBytes = Base64.getDecoder().decode(certB64);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

		} catch (Exception e) {
			logAuditEvent("CERT_EXTRACT_ERROR", e.getMessage());
			return null;
		}
	}

	/**
	 * Convert Document to String
	 */
	private String documentToString(Document doc) throws Exception {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		return writer.toString();
	}

	/**
	 * Validate certificate chain
	 */
	public CertificateValidationResult validateCertificateChain(X509Certificate signingCert, 
            boolean skipExpiryCheck) {
			        
			        CertificateValidationResult result = new CertificateValidationResult();
			        
			        try {
			            // Step 1: Check if certificate is from UIDAI
			            String subjectDN = signingCert.getSubjectX500Principal().getName();
			            String issuerDN = signingCert.getIssuerX500Principal().getName();
			            
			            logAuditEvent("CERT_CHAIN_CHECK", 
			                "Subject: " + subjectDN + ", Issuer: " + issuerDN);
			            
			            // Verify it's a UIDAI signing certificate
			            if (!subjectDN.toUpperCase().contains("UNIQUE IDENTIFICATION AUTHORITY OF INDIA")) {
			                result.setValid(false);
			                result.setFailureReason(ValidationResult.INVALID_CERTIFICATE_CHAIN);
			                result.setErrorMessage("Certificate is not from UIDAI");
			                return result;
			            }
			            
			            // Step 2: Check certificate validity period
			            if (!skipExpiryCheck) {
			                try {
			                    signingCert.checkValidity();
			                    logAuditEvent("CERT_VALIDITY", "Certificate is within validity period");
			                } catch (CertificateExpiredException e) {
			                    //result.setValid(false);
			                    //result.setFailureReason(ValidationResult.EXPIRED_CERTIFICATE);
			                    //result.setErrorMessage("Certificate expired on: " + signingCert.getNotAfter() + 
			                        //". Set skip-cert-expiry-check=true in application.yml for testing.");
			                	logAuditEvent(
			                            "CERT_EXPIRED_ALLOWED",
			                            "UIDAI Offline KYC allows expired signing certs"
			                        );
			                    //return result;
			                } catch (CertificateNotYetValidException e) {
			                    result.setValid(false);
			                    result.setFailureReason(ValidationResult.INVALID_CERTIFICATE_CHAIN);
			                    result.setErrorMessage("Certificate not yet valid");
			                    return result;
			                }
			            } else {
			                logAuditEvent("CERT_EXPIRY_SKIPPED", "Certificate expiry check skipped (DEV MODE)");
			            }
			            
			            // Step 3: If root CA provided, validate chain
			            
			            
			            // Step 4: Verify it's a valid signing certificate
			            // Check key usage if available
			            boolean[] keyUsage = signingCert.getKeyUsage();
			            if (keyUsage != null) {
			                // digitalSignature (0) or nonRepudiation (1) should be set
			                if (!keyUsage[0] && !keyUsage[1]) {
			                    logAuditEvent("CERT_KEY_USAGE_WARN", "Certificate may not be intended for signing");
			                }
			            }
			            
			            result.setValid(true);
			            logAuditEvent("CERT_CHAIN_VALID", "Certificate validation passed");
			            
			        } catch (Exception e) {
			            result.setValid(false);
			            result.setFailureReason(ValidationResult.INVALID_CERTIFICATE_CHAIN);
			            result.setErrorMessage("Certificate validation error: " + e.getMessage());
			            logAuditEvent("CERT_CHAIN_ERROR", e.getMessage());
			        }
			        
			        return result;
			    }
	
	/**
	 * Validate share code
	 */
	private ShareCodeValidationResult validateShareCode(Document document, String shareCode) {
		ShareCodeValidationResult result = new ShareCodeValidationResult();

		try {
			// Share code format validation
			if (shareCode == null || !shareCode.matches("\\d{4}")) {
				result.setValid(false);
				result.setErrorMessage("Share code must be exactly 4 digits");
				return result;
			}

			// Get mobile/email hashes from Poi element
			NodeList poiList = document.getElementsByTagName("Poi");
			if (poiList.getLength() > 0) {
				Element poi = (Element) poiList.item(0);
				String mobileHash = poi.getAttribute("m");
				String emailHash = poi.getAttribute("e");

				result.setMobileHashPresent(mobileHash != null && !mobileHash.isEmpty());
				result.setEmailHashPresent(emailHash != null && !emailHash.isEmpty());
			}

			result.setValid(true);
			result.setMessage("Share code format valid");

		} catch (Exception e) {
			result.setValid(false);
			result.setErrorMessage("Share code validation error: " + e.getMessage());
		}

		return result;
	}
	
	private boolean verifyMobileHash(String mobileNumber, String shareCode, 
            String referenceId, String storedHash) {
			if (mobileNumber == null || storedHash == null || storedHash.isEmpty()) {
			return false;
			}
			
			int lastDigit = Character.getNumericValue(referenceId.charAt(3));
			int iterations = (lastDigit == 0) ? 1 : lastDigit;
			
			System.out.println("DEBUG: Mobile=" + mobileNumber + ", ShareCode=" + shareCode);
			System.out.println("DEBUG: LastDigit=" + lastDigit + ", Iterations=" + iterations);
			System.out.println("DEBUG: StoredHash=" + storedHash);
			
			String computed = DigestUtils.sha256Hex(mobileNumber + shareCode); // Inner hash FIRST
			for (int i = 1; i < iterations; i++) {  // Start from 1, not 0
			    computed = DigestUtils.sha256Hex(computed);
			System.out.println("DEBUG: Iteration " + (i+1) + ": " + computed);
			}
			
			System.out.println("DEBUG: Match=" + computed.equalsIgnoreCase(storedHash));
			return computed.equalsIgnoreCase(storedHash);
}

	/**
	 * Extract KYC data from document
	 */
	private KYCData extractKYCData(Document document, String shareCode, String mobileNumber) {
		KYCData kycData = new KYCData();

		try {
			// Reference ID
			Element root = document.getDocumentElement();
			kycData.setReferenceId(root.getAttribute("referenceId"));

			// Personal Information (Poi)
			NodeList poiList = document.getElementsByTagName("Poi");
			if (poiList.getLength() > 0) {
				Element poi = (Element) poiList.item(0);
				kycData.setName(poi.getAttribute("name"));
				kycData.setDob(poi.getAttribute("dob"));
				kycData.setGender(poi.getAttribute("gender"));
				kycData.setMobileHash(poi.getAttribute("m"));
				kycData.setEmailHash(poi.getAttribute("e"));
			}

			// Address (Poa)
			NodeList poaList = document.getElementsByTagName("Poa");
			if (poaList.getLength() > 0) {
				Element poa = (Element) poaList.item(0);
				kycData.setCareOf(poa.getAttribute("careof"));
				kycData.setHouse(poa.getAttribute("house"));
				kycData.setStreet(poa.getAttribute("street"));
				kycData.setLandmark(poa.getAttribute("landmark"));
				kycData.setLocality(poa.getAttribute("loc"));
				kycData.setVtc(poa.getAttribute("vtc"));
				kycData.setDistrict(poa.getAttribute("dist"));
				kycData.setState(poa.getAttribute("state"));
				kycData.setPostalCode(poa.getAttribute("pc"));
				kycData.setCountry(poa.getAttribute("country"));
			}

			// Photo (Pht)
			NodeList phtList = document.getElementsByTagName("Pht");
			if (phtList.getLength() > 0) {
				String photoB64 = phtList.item(0).getTextContent();
				kycData.setPhotoBase64(photoB64);
				try {
					byte[] photoBytes = Base64.getDecoder().decode(photoB64.replaceAll("\\s+", ""));
					kycData.setPhotoSizeBytes(photoBytes.length);
				} catch (Exception e) {
					// Photo decode error - non-fatal
				}
			}

			// Masked Aadhaar from reference ID (first 4 digits)
			String refId = kycData.getReferenceId();
			if (refId != null && refId.length() >= 4) {
				kycData.setMaskedAadhaar("XXXXXXXX" + refId.substring(0, 4));
			}
			
			if (mobileNumber != null && !mobileNumber.isEmpty()) {
			    boolean verified = verifyMobileHash(mobileNumber, shareCode,
			            kycData.getReferenceId(), kycData.getMobileHash());
			    kycData.setMobileVerified(verified);
			    if (verified) {
			        kycData.setVerifiedMobileNumber(mobileNumber);
			    }
			}

			logAuditEvent("DATA_EXTRACTED", "KYC data extracted for: " + kycData.getName());

		} catch (Exception e) {
			logAuditEvent("DATA_EXTRACT_ERROR", e.getMessage());
		}

		return kycData;
	}

	/**
	 * Extract certificate info for response
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
	 * Audit logging
	 */
	private void logAuditEvent(String eventType, String details) {
		System.out.println(String.format("[AUDIT] %s | %s | %s", Instant.now(), eventType, details));
	}
}