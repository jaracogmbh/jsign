package net.jsign.testModel;

import net.jsign.jca.CustomSigningServiceInterface;
import net.jsign.jca.SigningService;
import net.jsign.jca.SigningServicePrivateKey;

import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.List;
import java.util.logging.Logger;

public class TestProviderService implements SigningService, CustomSigningServiceInterface {
    Logger logger = Logger.getLogger(TestProviderService.class.getName());

    String endpoint;
    String apiKey;
    String password;

    public TestProviderService(String keyStore, String parameters) {
        super();
        init(keyStore, parameters);
    }


    @Override
    public String getName() {
        return "TestProviderService";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        return List.of();
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        return new Certificate[0];
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        return null;
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        return new byte[0];
    }

    @Override
    public void validate(String keystore, String parameters) {if (keystore == null || keystore.isEmpty()) {
        logger.severe("No endpoint specified for the signing service in the keystore parameter!");
        throw new IllegalArgumentException("No endpoint specified for the signing service in the keystore parameter!");
    }
        logger.info("Validating storepass parameter");
        if (parameters == null || parameters.split("\\|").length != 2 ) {
            logger.severe("storepass " + parameters + " must specify the needed Signing Service parameters: <signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>");
            logger.severe("storepass: " + parameters);
            throw new IllegalArgumentException("storepass " + parameters + " must specify the needed Signing Service parameters: <signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>");
        }logger.info("Validating keystore: " + keystore + " with parameters: " + parameters);
    }

    @Override
    public void init(String keystore, String parameters) {
        logger.info("Initializing ExternalProviderService");
        try{
            validate(keystore, parameters);
        }catch (Exception e){
            logger.severe("Failed to validate ExternalProviderService parameters: " + e.getMessage());
            throw new RuntimeException(e);
        }
        String[] split = parameters.split("\\|");
        logger.info("Setting endpoint: " + keystore);
        this.endpoint = keystore;
        logger.info("Setting apikey: " + split[0]);
        this.apiKey = split[0];
        logger.info("Setting password: " + split[1]);
        this.password = split[1];
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apikey) {
        this.apiKey = apikey;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
