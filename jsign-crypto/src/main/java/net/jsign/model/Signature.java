package net.jsign.model;

public class Signature {
    String id;
    String signature;

    public Signature() {
    }
    public Signature(String id, String signature) {
        this.id = id;
        this.signature = signature;
    }

    public String getId() {
        return id;
    }

    public String getSignature() {
        return signature;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }


}
