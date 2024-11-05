/**
 * Copyright 2021 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.jsign.jca;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509KeyManager;

import net.jsign.DigestAlgorithm;
import net.jsign.KeyStoreBuilder;
import net.jsign.model.*;
import net.jsign.util.CertificateService;

/**
 * DigiCert ONE signing service.
 *
 * @since 4.0
 * @see <a href="https://one.digicert.com/signingmanager/swagger-ui/index.html?configUrl=/signingmanager/v3/api-docs/swagger-config">Secure Software Manager REST API</a>
 */
public class DigiCertOneSigningService implements SigningService {
    private CertificateService certificateService = new CertificateService();

    /** Cache of certificates indexed by id and alias */ 
    private final Map<String, Map<String, ?>> certificates = new HashMap<>();

    //private final RESTClient client;

    /** Pattern of a certificate or key identifier */
    private static final Pattern ID_PATTERN = Pattern.compile("[0-9a-f\\-]+");

    /**
     * Creates a new DigiCert ONE signing service.
     *
     * @param apiKey    the DigiCert ONE API access token
     * @param keystore  the keystore holding the client certificate to authenticate with the server
     * @param storepass the password of the keystore
     */
    public DigiCertOneSigningService(String apiKey, File keystore, String storepass) {
        this(apiKey);
    }

    /**
     * Creates a new DigiCert ONE signing service.
     *
     * @param endpoint  the URL of the DigiCert ONE host
     * @param apiKey    the DigiCert ONE API access token
     * @param keystore  the keystore holding the client certificate to authenticate with the server
     * @param storepass the password of the keystore
     */
    public DigiCertOneSigningService(String endpoint, String apiKey, File keystore, String storepass) {
        this(endpoint, apiKey);
    }

    /**
     * Creates a new DigiCert ONE signing service.
     *
     * @param apiKey     the DigiCert ONE API access token
     * @param keyManager the key manager to authenticate the client with the server
     */
    public DigiCertOneSigningService(String apiKey) {
        this(null, apiKey);
    }

    DigiCertOneSigningService(String endpoint, String apiKey) {
        if (endpoint == null) {
            endpoint = "https://clientauth.one.digicert.com";
        }

    }

    @Override
    public String getName() {
        return "DigiCertONE";
    }

    /**
     * Returns the certificate details
     *
     * @param alias the id or alias of the certificate
     */
    /*private Map<String, ?> getCertificateInfo(String alias) throws IOException {
        if (!certificates.containsKey(alias)) {
            Map<String, ?> response = client.get("certificates?" + (isIdentifier(alias) ? "id" : "alias") + "=" + alias);
            for (Object item : (Object[]) response.get("items")) {
                Map<String, ?> certificate = (Map<String, ?>) item;
                certificates.put((String) certificate.get("id"), certificate);
                certificates.put((String) certificate.get("alias"), certificate);
            }
        }

        return certificates.get(alias);
    }*/

    private boolean isIdentifier(String id) {
        return ID_PATTERN.matcher(id).matches();
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        List<String> aliases = new ArrayList<>();

        /*try {
            Map<String, ?> response = client.get("certificates?limit=100&certificate_status=ACTIVE");
            for (Object item : (Object[]) response.get("items")) {
                Map<String, ?> certificate = (Map<String, ?>) item;
                certificates.put((String) certificate.get("id"), certificate);
                certificates.put((String) certificate.get("alias"), certificate);

                aliases.add((String) certificate.get("alias"));
            }
        } catch (IOException e) {
            throw new KeyStoreException("Unable to retrieve DigiCert ONE certificate aliases", e);
        }
*/
        return aliases;
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        /*try {
            Map<String, ?> response = getCertificateInfo(alias);
            if (response == null) {
                throw new KeyStoreException("Unable to retrieve DigiCert ONE certificate '" + alias + "'");
            }

            List<String> encodedChain = new ArrayList<>();
            encodedChain.add((String) response.get("cert"));

            if (response.get("chain") != null) {
                for (Object certificate : (Object[]) response.get("chain")) {
                    encodedChain.add(((Map<String, String>) certificate).get("blob"));
                }
            }

            List<Certificate> chain = new ArrayList<>();
            for (String encodedCertificate : encodedChain) {
                chain.add(CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate))));
            }*/


        try{
            CertificateDTO certificate = certificateService.getCertificate(alias);
            List<String> encodedChain = new ArrayList<>();
            encodedChain.add((String) certificate.getCert());
            List<Chain> chainList = certificate.getChain();
            for(Chain c : chainList){
                encodedChain.add(c.getBlob());
            }
            List<Certificate> chain = new ArrayList<>();
            for (String encodedCertificate : encodedChain) {
                chain.add(CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate))));
            }
            //byte[] decoded = testEncode(cert);
            //chain.add(CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(cert))));
            return chain.toArray(new Certificate[0]);
        } catch (CertificateException e) {
            throw new KeyStoreException("Unable to retrieve DigiCert ONE certificate chain for '" + alias + "'", e);
        }
        /*} catch (IOException | CertificateException e) {
            throw new KeyStoreException("Unable to retrieve DigiCert ONE certificate '" + alias + "'", e);
        }*/
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        /*try {
            Map<String, ?> certificate = getCertificateInfo(alias);
            Map<String, Object> keypair = (Map<String, Object>) certificate.get("keypair");
            String keyId = (String) keypair.get("id");

            Map<String, ?> response = client.get("/keypairs/" + keyId);
            String algorithm = (String) response.get("key_alg");

            SigningServicePrivateKey key = new SigningServicePrivateKey(keyId, algorithm, this);
            key.getProperties().put("account", response.get("account"));
            return key;
        } catch (IOException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch DigiCert ONE private key for the certificate '" + alias + "'").initCause(e);
        }*/
        try{
            /*CertificateDTO certificate = certificateService.getCertificate(alias);
            String keyAlgorithm = certificate.getKeyAlgorithm();
            KeyPair keyPair = certificate.getKeyPair();
            String keyId = keyPair.getId();
            SigningServicePrivateKey key = new SigningServicePrivateKey(keyId, keyAlgorithm, this);
            key.getProperties().put("account", certificate.getAccount());*/
            return new SigningServicePrivateKey("egal", "RSA", this);
        } catch (Exception e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch DigiCert ONE private key for the certificate '" + alias + "'").initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        /*DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);

        Map<String, Object> request = new HashMap<>();
        request.put("account", privateKey.getProperties().get("account"));
        request.put("sig_alg", algorithm);
        request.put("hash", Base64.getEncoder().encodeToString(data));

        try {
            Map<String, ?> response = client.post("keypairs/" + privateKey.getId() + "/sign", JsonWriter.format(request));
            String value = (String) response.get("signature");*/
        Signature signature = certificateService.getSignature();
        System.out.println(signature);
        return Base64.getDecoder().decode(signature.getSignature());
       /* } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }*/
    }

  /* static KeyManager getKeyManager(File keystoreFile, String storepass) {
        try {
            KeyStore keystore = new KeyStoreBuilder().keystore(keystoreFile).storepass(storepass).build();

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keystore, storepass.toCharArray());

            return kmf.getKeyManagers()[0];
        } catch (Exception e) {
            throw new RuntimeException("Failed to load the client certificate for DigiCert ONE", e);
        }
    }*/

    public String getBase64Cert() throws IOException {
        String filePath = "output2.txt";
        try {
            // Load PEM file content
            StringBuilder res = new StringBuilder();
            File file = new File(filePath);
            Scanner myReader = new Scanner(file);
            while (myReader.hasNextLine()) {
                String data = myReader.nextLine();
                res.append(data);
            }

            // Remove PEM headers, footers, and all whitespace (including spaces, line breaks)
            System.out.println(res);
            //testEncode(res);
            return res.toString();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        return null;
    }

    public byte[] testEncode(String base64String){
        try {
            byte[] decodedBytes = Base64.getMimeDecoder().decode(base64String);
            String res  = new String(decodedBytes).replaceAll("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s+", "");
            System.out.println("res: " + res);
            return res.getBytes();
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid Base64 string: " + e.getMessage());
        }
        return null;
    }
}
