
package net.jsign.instatiation;

import net.jsign.jca.CustomProviderInstantiationService;

import net.jsign.testModel.TestProviderService;
import org.junit.Test;

import static org.junit.Assert.*;

public class CustomProviderServiceInstantiationServiceTest {

    CustomProviderInstantiationService underTest = new CustomProviderInstantiationService();

    @Test
    public void instantiateProviderServiceTest(){
        String keystore = "keystore|net.jsign.testModel.TestProviderService";
        String parameters = "apikey|password";
        TestProviderService result = (TestProviderService) underTest.instantiateProviderService(keystore, parameters);
        System.out.println(result.getClass());
        assertEquals(TestProviderService.class, result.getClass());
        assertEquals("apikey", result.getApiKey());
        assertEquals("password", result.getPassword());
        assertEquals("keystore", result.getEndpoint());
    }

    @Test
    public void extractingKeystoreAndClassNameTest(){
        String keystore = "keystore|net.jsign.testModel.TestProviderService";
        String[] result = underTest.extractingKeystoreAndClassName(keystore);
        assertEquals("keystore", result[0]);
        assertEquals("net.jsign.testModel.TestProviderService", result[1]);
    }

    @Test
    public void extractingKeystoreAndClassNameTestFailed(){
        String keystore = "keystore|";
        Exception e = assertThrows(IllegalArgumentException.class, () -> {
            underTest.extractingKeystoreAndClassName(keystore);
        });
        assertEquals("Invalid keystore format: " + keystore, e.getMessage());
    }
    @Test
    public void extractingKeystoreAndClassNameTestFailed2(){
        String keystore = "|net.jsign.testModel.TestProviderService";
        Exception e = assertThrows(IllegalArgumentException.class, () -> {
            underTest.extractingKeystoreAndClassName(keystore);
        });
        assertEquals("Invalid keystore format: " + keystore, e.getMessage());
    }

    @Test
    public void instantiateProviderServiceTestFailed() {
        String keystore = "keystore|net.jsign.testModel.EndpointProviderService";
        String parameters = "apikey|password";
        Exception e = assertThrows(RuntimeException.class, () -> {
            underTest.instantiateProviderService(keystore, parameters);
        });
        System.out.println(e.getMessage());
        System.out.println(e.getCause());
        assertEquals("Failed to instantiate CustomProviderService: net.jsign.testModel.EndpointProviderService", e.getMessage());
        assertEquals("java.lang.ClassNotFoundException: net.jsign.testModel.EndpointProviderService", e.getCause().toString());
    }


}

