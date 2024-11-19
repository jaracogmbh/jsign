package net.jsign.instantiation;

import net.jsign.exception.NoEndpointSpecifiedException;
import net.jsign.jca.CustomProviderService;
import net.jsign.jca.SigningService;

import java.lang.reflect.Constructor;
import java.util.logging.Logger;

public class CustomProviderServiceInstantiation {

    Logger logger = Logger.getLogger(CustomProviderServiceInstantiation.class.getName());

    public SigningService instantiateProviderService(String fullyQualifiedName, String keystore, String[] parameters) {
        try {
            Class<?> clazz = Class.forName(fullyQualifiedName);
            switch(clazz.getSimpleName()){
                case "CustomProviderService":
                    Constructor<?> constructor = clazz.getDeclaredConstructor(String.class, String.class, String.class, int.class, boolean.class, String.class, String.class, String.class, String.class);
                    Object obj = constructor.newInstance(keystore, parameters[0], parameters[1], Integer.parseInt(parameters[2]), Boolean.getBoolean(parameters[3]), parameters[4], parameters[5], parameters[6], parameters[7]);
                    return (SigningService) obj;
                    //return instantiateCustomProviderService(keystore, parameters);
                default: return null;
            }

        } catch (Exception e) {
            logger.severe("Failed to instantiate CustomProviderService: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public SigningService instantiateCustomProviderService(String keystore, String[] parameters) throws NoEndpointSpecifiedException {
        return new CustomProviderService(keystore, parameters[0], parameters[1], Integer.parseInt(parameters[2]), Boolean.getBoolean(parameters[3]), parameters[4], parameters[5], parameters[6], parameters[7]);
    }
}
