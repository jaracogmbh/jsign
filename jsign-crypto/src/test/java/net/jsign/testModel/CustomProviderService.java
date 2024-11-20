package net.jsign.testModel;

import net.jsign.jca.SigningService;
import net.jsign.jca.SigningServicePrivateKey;

import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.List;

public class CustomProviderService implements SigningService {

    public CustomProviderService(String keystore, String param1, String param2, int saltLength, boolean nonDecorateSignature, String param4, String param5, String param6, String param7) {
        super();
    }


    @Override
    public String getName() {
        return "CustomProviderService";
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
}
