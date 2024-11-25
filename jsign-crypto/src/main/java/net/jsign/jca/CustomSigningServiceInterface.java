package net.jsign.jca;

public interface CustomSigningServiceInterface {
    public void validate(String keystore, String parameters);
    public void init(String keystore, String parameters);
}
