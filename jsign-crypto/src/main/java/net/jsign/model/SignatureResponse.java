package net.jsign.model;

public class SignatureResponse {
    Long signTime;
    String signedHash;
    String validUntil;
    String certifacteId;
    String signReturnCode;
    String errorMessage;

    public SignatureResponse() {
    }

    public SignatureResponse(Long signTime, String signedHash, String validUntil, String certifacteId, String signReturnCode, String errorMessage) {
        this.signTime = signTime;
        this.signedHash = signedHash;
        this.validUntil = validUntil;
        this.certifacteId = certifacteId;
        this.signReturnCode = signReturnCode;
        this.errorMessage = errorMessage;
    }

    public Long getSignTime() {
        return signTime;
    }

    public void setSignTime(Long signTime) {
        this.signTime = signTime;
    }

    public String getSignedHash() {
        return signedHash;
    }

    public void setSignedHash(String signedHash) {
        this.signedHash = signedHash;
    }

    public String getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(String validUntil) {
        this.validUntil = validUntil;
    }

    public String getCertifacteId() {
        return certifacteId;
    }

    public void setCertifacteId(String certifacteId) {
        this.certifacteId = certifacteId;
    }

    public String getSignReturnCode() {
        return signReturnCode;
    }

    public void setSignReturnCode(String signReturnCode) {
        this.signReturnCode = signReturnCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
