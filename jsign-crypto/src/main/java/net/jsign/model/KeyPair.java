package net.jsign.model;

public class KeyPair {
    String id;
    String alias;

    public KeyPair() {
    }

    public KeyPair(String id, String alias) {
        this.id = id;
        this.alias = alias;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
}
