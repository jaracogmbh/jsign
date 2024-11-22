package net.jsign;

import org.junit.Test;
import org.mockito.Mockito;

import java.security.Provider;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class KeyStoreTest {
    KeyStoreType underTest = KeyStoreType.CUSTOMPROVIDER;
    @Test
    public void testGetProviderSuccess(){
       KeyStoreBuilder params = Mockito.mock(KeyStoreBuilder.class);
       when(params.storepass()).thenReturn("apiKey|password");
       when(params.keystore()).thenReturn("keystore|net.jsign.testModel.TestProviderService");
       underTest.validate(params);
       Provider result = underTest.getProvider(params);
       assertNotNull(result);
    }

    @Test
    public void testGetProviderFailed() {
        KeyStoreBuilder params = Mockito.mock(KeyStoreBuilder.class);
        Exception e = assertThrows(RuntimeException.class, () -> {
            underTest.getProvider(params);
        });
        assertEquals("Failed to instantiate CustomProviderService! Provider was null.", e.getMessage());
    }
}
