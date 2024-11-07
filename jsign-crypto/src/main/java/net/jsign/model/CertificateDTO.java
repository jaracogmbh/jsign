package net.jsign.model;


import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIncludeProperties;

import java.util.List;
import java.util.Objects;


public class CertificateDTO {
    String id;
    String cert;
    List<Chain> chain;


    public CertificateDTO() {
    }

    public CertificateDTO(String id, String cert, List<Chain> chain) {
        this.id = id;
        this.cert = cert;
        this.chain = chain;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCert() {
        return cert;
    }

    public void setCert(String cert) {
        this.cert = cert;
    }

    public List<Chain> getChain() {
        return chain;
    }

    public void setChain(List<Chain> chain) {
        this.chain = chain;
    }


    @Override
    public String toString() {
        return "CertificateDTO{" +
                "id='" + id + '\'' +
                ", cert='" + cert + '\'' +
                ", chain=" + chain +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CertificateDTO that = (CertificateDTO) o;
        return Objects.equals(id, that.id) && Objects.equals(cert, that.cert) && Objects.equals(chain, that.chain);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, cert, chain);
    }
}
