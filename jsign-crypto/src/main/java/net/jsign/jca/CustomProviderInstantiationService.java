package net.jsign.jca;


import java.lang.reflect.Constructor;
import java.util.logging.Logger;

public class CustomProviderInstantiationService {

    Logger logger = Logger.getLogger(CustomProviderInstantiationService.class.getName());

    public SigningService instantiateProviderService(String keystore, String parameters) {
        String[] split = this.extractingKeystoreAndClassName(keystore);
        try {
            Class<?> clazz = Class.forName(split[1]);
            Constructor<?> constructor = clazz.getDeclaredConstructor(String.class, String.class);
            return (SigningService) constructor.newInstance(split[0], parameters);
        } catch (Exception e) {
            String message = "Failed to instantiate CustomProviderService: " + e.getMessage();
            logger.severe(message);
            throw new RuntimeException(message, e);
        }
    }

    public String[] extractingKeystoreAndClassName(String keystore) {
        if (keystore.split("\\|").length != 2 || this.checkIfStringisEmpty(keystore.split("\\|"))) {
            throw new IllegalArgumentException("Invalid keystore format: " + keystore);
        }else {
            String[] split = keystore.split("\\|");
            return split;
        }
    }

    private boolean checkIfStringisEmpty(String[] values) {
        for (String value : values) {
            if (value.isEmpty()) {
                return true;
            }
        }
        return false;
    }

}
