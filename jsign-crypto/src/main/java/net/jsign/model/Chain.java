package net.jsign.model;

public class Chain {
    Object type;
    String blob;

    public Chain() {
    }

    public Chain(String type, String blob) {
        this.type = type;
        this.blob = blob;
    }
    public Object getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getBlob() {
        return blob;
    }

    public void setBlob(String blob) {
        this.blob = blob;
    }
}
