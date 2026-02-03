package com.sberbank.kyc.model;

/**
 * Data Transfer Object for KYC extracted data from Offline Aadhaar XML.
 * 
 * Contains:
 * - Proof of Identity (POI): Name, DOB, Gender
 * - Proof of Address (POA): Complete address details
 * - Photo: Base64 encoded JPEG photograph
 * - Reference ID and Masked Aadhaar
 * 
 * @author Sberbank India - Enterprise Architecture
 * @version 2.0
 */
public class KYCData {
    
    // Identity fields
    private String referenceId;
    private String maskedAadhaar;
    private String name;
    private String dob;
    private String gender;
    private String mobileHash;
    private String emailHash;

    // Address fields
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

    // Photo fields
    private String photoBase64;
    private int photoSizeBytes;
    
    //mobile field
    private String verifiedMobileNumber;
    private boolean mobileVerified;

    // ==================== GETTERS AND SETTERS ====================

    // Reference ID
    public String getReferenceId() {
        return referenceId;
    }

    public void setReferenceId(String referenceId) {
        this.referenceId = referenceId;
    }

    // Masked Aadhaar
    public String getMaskedAadhaar() {
        return maskedAadhaar;
    }

    public void setMaskedAadhaar(String maskedAadhaar) {
        this.maskedAadhaar = maskedAadhaar;
    }

    // Name
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    // Date of Birth
    public String getDob() {
        return dob;
    }

    public void setDob(String dob) {
        this.dob = dob;
    }

    // Gender
    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    // Mobile Hash
    public String getMobileHash() {
        return mobileHash;
    }

    public void setMobileHash(String mobileHash) {
        this.mobileHash = mobileHash;
    }

    // Email Hash
    public String getEmailHash() {
        return emailHash;
    }

    public void setEmailHash(String emailHash) {
        this.emailHash = emailHash;
    }

    // Care Of
    public String getCareOf() {
        return careOf;
    }

    public void setCareOf(String careOf) {
        this.careOf = careOf;
    }

    // House
    public String getHouse() {
        return house;
    }

    public void setHouse(String house) {
        this.house = house;
    }

    // Street
    public String getStreet() {
        return street;
    }

    public void setStreet(String street) {
        this.street = street;
    }

    // Landmark
    public String getLandmark() {
        return landmark;
    }

    public void setLandmark(String landmark) {
        this.landmark = landmark;
    }

    // Locality
    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    // VTC (Village/Town/City)
    public String getVtc() {
        return vtc;
    }

    public void setVtc(String vtc) {
        this.vtc = vtc;
    }

    // District
    public String getDistrict() {
        return district;
    }

    public void setDistrict(String district) {
        this.district = district;
    }

    // State
    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    // Postal Code
    public String getPostalCode() {
        return postalCode;
    }

    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    // Country
    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    // Photo Base64
    public String getPhotoBase64() {
        return photoBase64;
    }

    public void setPhotoBase64(String photoBase64) {
        this.photoBase64 = photoBase64;
    }

    // Photo Size in Bytes
    public int getPhotoSizeBytes() {
        return photoSizeBytes;
    }

    public void setPhotoSizeBytes(int photoSizeBytes) {
        this.photoSizeBytes = photoSizeBytes;
    }
    
    //mobile
    public String getVerifiedMobileNumber() {
        return verifiedMobileNumber;
    }

    public void setVerifiedMobileNumber(String verifiedMobileNumber) {
        this.verifiedMobileNumber = verifiedMobileNumber;
    }

    public boolean isMobileVerified() {
        return mobileVerified;
    }

    public void setMobileVerified(boolean mobileVerified) {
        this.mobileVerified = mobileVerified;
    }

    // ==================== UTILITY METHODS ====================

    /**
     * Get formatted full address as a single string
     * @return Concatenated address string
     */
    public String getFullAddress() {
        StringBuilder sb = new StringBuilder();
        
        if (house != null && !house.isEmpty()) sb.append(house).append(", ");
        if (street != null && !street.isEmpty()) sb.append(street).append(", ");
        if (landmark != null && !landmark.isEmpty()) sb.append(landmark).append(", ");
        if (locality != null && !locality.isEmpty()) sb.append(locality).append(", ");
        if (vtc != null && !vtc.isEmpty()) sb.append(vtc).append(", ");
        if (district != null && !district.isEmpty()) sb.append(district).append(", ");
        if (state != null && !state.isEmpty()) sb.append(state).append(" - ");
        if (postalCode != null && !postalCode.isEmpty()) sb.append(postalCode).append(", ");
        if (country != null && !country.isEmpty()) sb.append(country);
        
        return sb.toString().replaceAll(", $", "");
    }

    /**
     * Check if photo is available
     * @return true if photo base64 data exists
     */
    public boolean hasPhoto() {
        return photoBase64 != null && !photoBase64.isEmpty();
    }

    /**
     * Check if address is complete for banking requirements
     * @return true if minimum required address fields are present
     */
    public boolean isAddressComplete() {
        return district != null && !district.isEmpty() &&
               state != null && !state.isEmpty() &&
               postalCode != null && postalCode.matches("\\d{6}");
    }

    @Override
    public String toString() {
        return "KYCData{" +
                "referenceId='" + referenceId + '\'' +
                ", maskedAadhaar='" + maskedAadhaar + '\'' +
                ", name='" + name + '\'' +
                ", dob='" + dob + '\'' +
                ", gender='" + gender + '\'' +
                ", state='" + state + '\'' +
                ", postalCode='" + postalCode + '\'' +
                ", hasPhoto=" + hasPhoto() +
                ", mobileVerified=" + mobileVerified +
                ", verifiedMobileNumber='" + (mobileVerified ? verifiedMobileNumber : "N/A") + '\'' +
                '}';
    }
}
