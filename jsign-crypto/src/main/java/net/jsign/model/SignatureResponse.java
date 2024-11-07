package net.jsign.model;

import java.util.Objects;

public class SignatureResponse {
    Long signTime;
    String signedHash;
    String validUntil;
    String certificateId;
    String signCertificate;
    String signReturnCode;
    String errorMessage;

    public SignatureResponse() {
    }

    public SignatureResponse(Long signTime, String signedHash, String validUntil, String certifacteId, String signCertificate, String signReturnCode, String errorMessage) {
        this.signTime = signTime;
        this.signedHash = signedHash;
        this.validUntil = validUntil;
        this.certificateId = certifacteId;
        this.signCertificate = signCertificate;
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

    public String getCertificateId() {
        return certificateId;
    }

    public void setCertificateId(String certificateId) {
        this.certificateId = certificateId;
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

    public String getSignCertificate() {
        return signCertificate;
    }

    public void setSignCertificate(String signCertificate) {
        this.signCertificate = signCertificate;
    }

    @Override
    public String toString() {
        return "SignatureResponse{" +
                "signTime=" + signTime +
                ", signedHash='" + signedHash + '\'' +
                ", validUntil='" + validUntil + '\'' +
                ", certificateId='" + certificateId + '\'' +
                ", signCertificate='" + signCertificate + '\'' +
                ", signReturnCode='" + signReturnCode + '\'' +
                ", errorMessage='" + errorMessage + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SignatureResponse that = (SignatureResponse) o;
        return Objects.equals(signTime, that.signTime) && Objects.equals(signedHash, that.signedHash) && Objects.equals(validUntil, that.validUntil) && Objects.equals(certificateId, that.certificateId) && Objects.equals(signCertificate, that.signCertificate) && Objects.equals(signReturnCode, that.signReturnCode) && Objects.equals(errorMessage, that.errorMessage);
    }

    @Override
    public int hashCode() {
        return Objects.hash(signTime, signedHash, validUntil, certificateId, signCertificate, signReturnCode, errorMessage);
    }
}
