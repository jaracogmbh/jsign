package net.jsign.model;

import java.util.List;

public class CertificateList {
    List<CertificateDTO> certificates;

    public CertificateList() {
    }

    public CertificateList(List<CertificateDTO> certificates) {
        this.certificates = certificates;
    }

    public List<CertificateDTO> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<CertificateDTO> certificates) {
        this.certificates = certificates;
    }
}
