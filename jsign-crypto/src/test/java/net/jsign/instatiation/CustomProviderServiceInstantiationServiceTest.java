/*
package net.jsign.instatiation;

import net.jsign.exception.NotABooleanValueException;
import net.jsign.exception.NotACorrectIntegerValueException;
import net.jsign.instantiation.CustomProviderServiceInstantiation;
import net.jsign.testModel.CustomProviderService;
import org.junit.Test;

import static org.junit.Assert.*;

public class CustomProviderServiceInstantiationServiceTest {

    CustomProviderServiceInstantiation underTest = new CustomProviderServiceInstantiation();

    @Test
    public void instantiateProviderServiceTest(){
        String fullyQualifiedName = "net.jsign.testModel.CustomProviderService";
        String keystore = "keystore";
        String[] parameters = new String[]{"param1", "blaa", "32", "true", "param4", "param5", "param6", "param7"};
        CustomProviderService result = (CustomProviderService) underTest.instantiateProviderService(fullyQualifiedName, keystore, parameters);
        System.out.println(result.getName());
        assertEquals("CustomProviderService", result.getName());
        assertEquals(CustomProviderService.class, result.getClass());
    }

    @Test
    public void instatiateProviderServiceTestFailed() throws ClassNotFoundException {
        String fullyQualifiedName = "net.jsign.testModel.CustomProviderService";
        String keystore = "keystore";
        Class<?> clazz =  Class.forName(fullyQualifiedName);
        String[] parameters = new String[]{"param1", "blaa", "32o", "true", "param4", "param5", "param6", "param7"};
        Exception e = assertThrows(NotACorrectIntegerValueException.class, () -> {
            underTest.instantiateCustomProviderService(clazz, keystore, parameters);
        });
        assertEquals("The value of salt length is not an integer value", e.getMessage());
    }

    @Test
    public void instatiateProviderServiceTestFailed2() throws ClassNotFoundException {
        String fullyQualifiedName = "net.jsign.testModel.CustomProviderService";
        String keystore = "keystore";
        Class<?> clazz =  Class.forName(fullyQualifiedName);
        String[] parameters = new String[]{"param1", "blaa", "32", "truee", "param4", "param5", "param6", "param7"};
        Exception e = assertThrows(NotABooleanValueException.class, () -> {
            underTest.instantiateCustomProviderService(clazz, keystore, parameters);
        });
        assertEquals("The value of non decorate signature is not a boolean value", e.getMessage());
    }
}
*/
