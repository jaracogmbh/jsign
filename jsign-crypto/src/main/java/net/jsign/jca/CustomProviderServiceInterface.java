package net.jsign.jca;

public interface CustomProviderServiceInterface {

    public void validate(String keystore, String parameters);
    public void init(String keystore, String parameters);

}
