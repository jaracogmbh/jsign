package net.jsign.instantiation;


import net.jsign.exceptions.NotABooleanValueException;
import net.jsign.exceptions.NotACorrectIntegerValueException;
import net.jsign.jca.SigningService;
import net.jsign.util.ParameterChecker;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.logging.Logger;

public class CustomProviderServiceInstantiation {

    Logger logger = Logger.getLogger(CustomProviderServiceInstantiation.class.getName());
    ParameterChecker checker = new ParameterChecker();

    public SigningService instantiateProviderService(String fullyQualifiedName, String keystore, String[] parameters) {
        try {
            Class<?> clazz = Class.forName(fullyQualifiedName);
            switch(clazz.getSimpleName()){
                case "CustomProviderService":
                    logger.info("Instantiating CustomProviderService");
                    Object obj = this.instantiateCustomProviderService(clazz, keystore, parameters);
                    return (SigningService) obj;
                default: return null;
            }

        } catch (Exception e) {
            logger.severe("Failed to instantiate CustomProviderService: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public SigningService instantiateCustomProviderService(Class<?> clazz, String keystore, String[] parameters) throws NoSuchMethodException, NotABooleanValueException, NotACorrectIntegerValueException, InvocationTargetException, InstantiationException, IllegalAccessException {
        Constructor<?> constructor = clazz.getDeclaredConstructor(String.class, String.class, String.class, int.class, boolean.class, String.class, String.class, String.class, String.class);
        boolean nonDecorateSignature;
        int saltLength;
        logger.info("Verifying the values of non decorate signature parameters");
        if(checker.checkIfBoolean(parameters[3])) {
            nonDecorateSignature = Boolean.parseBoolean(parameters[3]);
        }else {
            logger.severe("The value of non decorate signature is not a boolean value");
            throw new NotABooleanValueException("The value of non decorate signature is not a boolean value");
        }
        logger.info("Verifying the values of salt length parameters");
        if(checker.checkIfInteger(parameters[2])) {
            saltLength = Integer.parseInt(parameters[2]);
        }
        else{
            logger.severe("The value of salt length is not an integer value");
            throw new NotACorrectIntegerValueException("The value of salt length is not an integer value");
        }
        return (SigningService) constructor.newInstance(keystore, parameters[0], parameters[1], saltLength, nonDecorateSignature, parameters[4], parameters[5], parameters[6], parameters[7]);
    }

}
