package net.jsign;

import net.jsign.exception.NoEndpointSpecifiedException;
import net.jsign.exception.NotABooleanValueException;
import net.jsign.exception.NotCorrectIntegerValueException;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

public class KeyStoreTest {

    KeyStoreType underTest = KeyStoreType.CUSTOMPROVIDER;

    @Test
    public void validateSuccessTest(){
        KeyStoreBuilder keyStoreparams = new KeyStoreBuilder();
        keyStoreparams.storepass("algSig|MFG1|32|true|group|1234|user|passwort1234");
        try {
            underTest.validate(keyStoreparams);
            assertTrue(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void validateFailureTest(){
        KeyStoreBuilder keyStoreparams = new KeyStoreBuilder();
        keyStoreparams.storepass("algSig|MFG1|32||group|1234|user|passwort1234");
        String[] split = keyStoreparams.storepass().split("\\|");
        System.out.println(split.length);
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            underTest.validate(keyStoreparams);
        });
        assertEquals("storepass " + keyStoreparams.parameterName() + " must specify the needed Signing Service parameters: <signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>", exception.getMessage());
    }

    @Test
    public void validateFailureTest2(){
        KeyStoreBuilder keyStoreparams = new KeyStoreBuilder();
        keyStoreparams.storepass("algSig|MFG1|32|true|group|1234|user");
        String[] split = keyStoreparams.storepass().split("\\|");
        System.out.println(split.length);
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            underTest.validate(keyStoreparams);
        });
        assertEquals("storepass " + keyStoreparams.parameterName() + " must specify the needed Signing Service parameters: <signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>", exception.getMessage());
    }

    @Test
    public void getProviderSuccessTest(){
        KeyStoreBuilder keyStoreparams = new KeyStoreBuilder();
        keyStoreparams.keystore("http://localhost:8080");
        keyStoreparams.storepass("algSig|MFG1|32|true|group|1234|user|passwort1234");
        try {
            underTest.getProvider(keyStoreparams);
            assertTrue(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void getProviderFailBooleanTest(){
        KeyStoreBuilder keyStoreparams = new KeyStoreBuilder();
        keyStoreparams.storepass("algSig|MFG1|32|tue|group|1234|user|passwort1234");
        keyStoreparams.keypass("http://localhost:8080");
        Exception exception = assertThrows(NotABooleanValueException.class, () -> {
            underTest.getProvider(keyStoreparams);
        });
        assertEquals("The value of non decorate signature is not a boolean value", exception.getMessage());
    }

    @Test
    public void getProviderFailIntegerTest(){
        KeyStoreBuilder keyStoreparams = new KeyStoreBuilder();
        keyStoreparams.storepass("algSig|MFG1|keineNummer|true|group|1234|user|passwort1234");
        keyStoreparams.keypass("http://localhost:8080");
        Exception exception = assertThrows(NotCorrectIntegerValueException.class, () -> {
            underTest.getProvider(keyStoreparams);
        });
        assertEquals("The value of salt length is not an integer value", exception.getMessage());
    }

    @Test
    public void getProviderFailIntegerTest2(){
        KeyStoreBuilder keyStoreparams = new KeyStoreBuilder();
        keyStoreparams.storepass("algSig|MFG1|32|true|group|keineNummer|user|passwort1234");
        keyStoreparams.keypass("http://localhost:8080");
        Exception exception = assertThrows(NotCorrectIntegerValueException.class, () -> {
            underTest.getProvider(keyStoreparams);
        });
        assertEquals("The value of service id is not an integer value", exception.getMessage());
    }

    @Test
    public void getProviderNoEndpointTest(){
        KeyStoreBuilder keyStoreparams = new KeyStoreBuilder();
        keyStoreparams.storepass("algSig|MFG1|32|true|group|1234|user|keineNummer");
        keyStoreparams.keypass("http://localhost:8080");
        Exception exception = assertThrows(NoEndpointSpecifiedException.class, () -> {
            underTest.getProvider(keyStoreparams);
        });
        assertEquals("No endpoint specified for the signing service service", exception.getMessage());
    }
}
