package net.jsign.model;


import java.util.List;

public class CertificateDTO {
    String id;
    String cert;
    List<Chain> chain;
    String keyAlgorithm;
    KeyPair keyPair;
    Account account;

    public CertificateDTO() {
    }

    public CertificateDTO(String id, String cert, List<Chain> chain, String keyAlgorithm, KeyPair keyPair, Account account) {
        this.id = id;
        this.cert = cert;
        this.chain = chain;
        this.keyAlgorithm = keyAlgorithm;
        this.keyPair = keyPair;
        this.account = account;
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

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public Account getAccount() {
        return account;
    }

    public void setAccount(Account account) {
        this.account = account;
    }
}
