package com.sberbank.kyc.model;

public class KYCApiResponse {
	
	private String requestId;
    private boolean success;
    private String validationResult;
    private String errorCode;
    private String errorMessage;
    private boolean signatureValid;
    private boolean certificateValid;
    private boolean shareCodeValid;
    private KYCDataDTO kycData;
    
    // Getters and Setters
    public void setRequestId(String id) { this.requestId = id; }
    public String getRequestId() { return requestId; }
    public void setSuccess(boolean s) { this.success = s; }
    public boolean isSuccess() { return success; }
    public void setValidationResult(String r) { this.validationResult = r; }
    public String getValidationResult() { return validationResult; }
    public void setErrorCode(String c) { this.errorCode = c; }
    public void setErrorMessage(String m) { this.errorMessage = m; }
    public void setSignatureValid(boolean v) { this.signatureValid = v; }
    public void setCertificateValid(boolean v) { this.certificateValid = v; }
    public void setShareCodeValid(boolean v) { this.shareCodeValid = v; }
    public void setKycData(KYCDataDTO d) { this.kycData = d; }


    public boolean isSignatureValid() {
        return signatureValid;
    }

    public boolean isCertificateValid() {
        return certificateValid;
    }

    public boolean isShareCodeValid() {
        return shareCodeValid;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public KYCDataDTO getKycData() {
        return kycData;
    }

    
    public static class KYCDataDTO {
        private String referenceId;
        private String maskedAadhaar;
        private String name;
        private String dob;
        private String gender;
        private AddressDTO address;
        private boolean photoAvailable;
        private boolean mobileVerified;
        private String verifiedMobileNumber;
        private String photoBase64;
        
        // Getters and Setters
        public void setReferenceId(String id) { this.referenceId = id; }
        public void setMaskedAadhaar(String m) { this.maskedAadhaar = m; }
        public void setName(String n) { this.name = n; }
        public void setDob(String d) { this.dob = d; }
        public void setGender(String g) { this.gender = g; }
        public void setAddress(AddressDTO a) { this.address = a; }
        public void setPhotoAvailable(boolean p) { this.photoAvailable = p; }
        
        
        public boolean isMobileVerified() { return mobileVerified; }
        public void setMobileVerified(boolean mobileVerified) { this.mobileVerified = mobileVerified; }
        public String getVerifiedMobileNumber() { return verifiedMobileNumber; }
        public void setVerifiedMobileNumber(String verifiedMobileNumber) { this.verifiedMobileNumber = verifiedMobileNumber; }
        public String getPhotoBase64() { return photoBase64; }
        public void setPhotoBase64(String photoBase64) { this.photoBase64 = photoBase64; }
        
        public String getReferenceId() {
            return referenceId;
        }

        public String getMaskedAadhaar() {
            return maskedAadhaar;
        }

        public String getName() {
            return name;
        }

        public String getDob() {
            return dob;
        }

        public String getGender() {
            return gender;
        }

        public AddressDTO getAddress() {
            return address;
        }

        public boolean isPhotoAvailable() {
            return photoAvailable;
        }
    }
    
    public static class AddressDTO {
        private String careOf;
        private String house;
        private String street;
        private String landmark;
        private String locality;
        private String vtc;
        private String district;
        private String state;
        private String postalCode;
        private String country;
        
        // Getters and Setters
        public void setCareOf(String c) { this.careOf = c; }
        public void setHouse(String h) { this.house = h; }
        public void setStreet(String s) { this.street = s; }
        public void setLandmark(String l) { this.landmark = l; }
        public void setLocality(String l) { this.locality = l; }
        public void setVtc(String v) { this.vtc = v; }
        public void setDistrict(String d) { this.district = d; }
        public void setState(String s) { this.state = s; }
        public void setPostalCode(String p) { this.postalCode = p; }
        public void setCountry(String c) { this.country = c; }
        
        public String getCareOf() {
            return careOf;
        }

        public String getHouse() {
            return house;
        }

        public String getStreet() {
            return street;
        }

        public String getLandmark() {
            return landmark;
        }

        public String getLocality() {
            return locality;
        }

        public String getVtc() {
            return vtc;
        }

        public String getDistrict() {
            return district;
        }

        public String getState() {
            return state;
        }

        public String getPostalCode() {
            return postalCode;
        }

        public String getCountry() {
            return country;
        }
    }

}
