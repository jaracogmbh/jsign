package net.jsign.model;


import java.util.List;

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

}
