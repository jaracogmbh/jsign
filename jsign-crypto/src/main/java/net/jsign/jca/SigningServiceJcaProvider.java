package net.jsign.jca;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

import net.jsign.DigestAlgorithm;

/**
 * JCA Provider using a signing service.
 *
 * <p>Example:</p>
 * <pre>
 * Provider provider = new SigningServiceJcaProvider(new CustomProviderService(endpoint, apiKey)); (sorry Azure)
 * KeyStore keystore = KeyStore.getInstance("SigningService", provider);
 * </pre>
 *
 */
public class SigningServiceJcaProvider extends Provider {

    public SigningServiceJcaProvider(SigningService service) {
        super(service.getName(), 1.0, service.getName() + " signing service provider");

        AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
            // Registering SigningService explicitly for the KeyStore
            putService(new ProviderService(this, "KeyStore", "SigningService", SigningServiceKeyStore.class.getName(), () -> new SigningServiceKeyStore(service)));

            //  registration as KeyStore.CUSTOMPROVIDER for backwards compatibility or specific naming
            put("KeyStore." + service.getName().toUpperCase(), "net.jsign.jca.SigningServiceKeyStore");
            for (String alg : new String[]{"RSA", "ECDSA"}) {
                for (DigestAlgorithm digest : DigestAlgorithm.values()) {
                    if (digest != DigestAlgorithm.MD5) {
                        String algorithm = digest.name() + "with" + alg;
                        putService(new ProviderService(this, "Signature", algorithm, SigningServiceSignature.class.getName(), () -> new SigningServiceSignature(algorithm)));
                    }
                }
            }
            return null;
        });
    }
}