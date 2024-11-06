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

import net.jsign.exception.FailedCertificateExtractionException;
import net.jsign.exception.FailedSignatureExtractionException;
import net.jsign.exception.NoEndpointSpecifiedException;
import net.jsign.exception.SignRequestFailedException;
import net.jsign.model.CertificateDTO;
import net.jsign.model.Chain;
import net.jsign.model.SignatureResponse;
import net.jsign.util.CertificateService;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * DigiCert ONE signing service.
 *
 * @since 4.0
 * @see <a href="https://one.digicert.com/signingmanager/swagger-ui/index.html?configUrl=/signingmanager/v3/api-docs/swagger-config">Secure Software Manager REST API</a>
 */
public class DigiCertOneSigningService implements SigningService {
    private CertificateService certificateService = new CertificateService();
    private final Logger logger = Logger.getLogger(DigiCertOneSigningService.class.getName());

    /** Cache of certificates indexed by id and alias */ 
    private final List<Certificate> certificates = new ArrayList<>();
    private String endpoint;
    String signAlgorithm;
    String mgfAlgorithm;
    int saltLength;
    boolean nonDecorateSignature;
    String group;
    int serviceId;
    String user;
    String auth;

    //private final RESTClient client;

    /** Pattern of a certificate or key identifier */
    private static final Pattern ID_PATTERN = Pattern.compile("[0-9a-f\\-]+");

    /**
     * Creates a new DigiCert ONE based signing service.
     *
     * @param endpoint the URL of the DigiCert ONE service
     * @param signAlgorithm the signature algorithm to use
     * @param mgfAlgorithm the mask generation function to use
     * @param saltLength the length of the salt
     * @param nonDecorateSignature true to disable the signature decoration
     * @param group the group of the certificate
     * @param serviceId the id of the service
     * @param user the user id
     * @param auth the authentication token
     */

    public DigiCertOneSigningService(
            String endpoint,
            String signAlgorithm,
            String mgfAlgorithm,
            int saltLength,
            boolean nonDecorateSignature,
            String group,
            int serviceId,
            String user,
            String auth
    ) throws NoEndpointSpecifiedException {
        if (endpoint == null) {
            throw new NoEndpointSpecifiedException("No endpoint specified for the signing service service");
        }else{
            logger.info("Setting endpoint to: " + endpoint);
            this.endpoint = endpoint;
        }
        logger.info("Setting sign algorithm to: " + signAlgorithm);
        this.signAlgorithm = signAlgorithm;
        logger.info("Setting mask generation function to: " + mgfAlgorithm);
        this.mgfAlgorithm = mgfAlgorithm;
        logger.info("Setting salt length to: " + saltLength);
        this.saltLength = saltLength;
        logger.info("Setting non decorate signature to: " + nonDecorateSignature);
        this.nonDecorateSignature = nonDecorateSignature;
        logger.info("Setting group to: " + group);
        this.group = group;
        logger.info("Setting service id to: " + serviceId);
        this.serviceId = serviceId;
        logger.info("Setting user to: " + user);
        this.user = user;
        this.auth = auth;
    }

    @Override
    public String getName() {
        return "DigiCertONE";
    }

    private boolean isIdentifier(String id) {
        return ID_PATTERN.matcher(id).matches();
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        List<String> aliases = new ArrayList<>();

        logger.info("Skipping the keystore aliases");

        return aliases;
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        logger.info("Getting certificate chain from server");
        try{
            CertificateDTO certificate = certificateService.getCertificate(alias, endpoint, auth);
            List<String> encodedChain = new ArrayList<>();
            encodedChain.add((String) certificate.getCert());
            List<Chain> chainList = certificate.getChain();
            for(Chain c : chainList){
                encodedChain.add(c.getBlob());
            }
            List<Certificate> chain = new ArrayList<>();
            for (String encodedCertificate : encodedChain) {
                Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate)));
                chain.add(cert);
                certificates.add(cert);
            }
            return chain.toArray(new Certificate[0]);
        } catch (CertificateException | FailedCertificateExtractionException e) {
            logger.severe("Failed to get certificate chain from server for user with id: " + user);
            throw new KeyStoreException("Failed to get certificate from server for user with id: " + user, e);
        }

    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        try{
            logger.info("Skipping this methode");
            return new SigningServicePrivateKey("egal", "RSA", this);
        } catch (Exception e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch DigiCert ONE private key for the certificate '" + alias + "'").initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException, SignRequestFailedException, FailedSignatureExtractionException {
        logger.info("Signing data with certificate");
        SignatureResponse signature = certificateService.getSignature(endpoint, data, signAlgorithm, mgfAlgorithm, saltLength, nonDecorateSignature, group, serviceId, user, auth);
        if(signature.getSignReturnCode() == "FAILED"){
            logger.info("Failed to sign data with certificate!");
            String errorMessage = signature.getErrorMessage();
            logger.info("An error occured while creating the signature on the server site: " + signature.getErrorMessage());
            throw new SignRequestFailedException(errorMessage);
        }else{
            logger.info("Successfully signed data with certificate");
            return Base64.getDecoder().decode(signature.getSignedHash());
        }

    }



    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public CertificateService getCertificateService() {
        return certificateService;
    }


    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }

    public String getSignAlgorithm() {
        return signAlgorithm;
    }

    public void setSignAlgorithm(String signAlgorithm) {
        this.signAlgorithm = signAlgorithm;
    }

    public String getMgfAlgorithm() {
        return mgfAlgorithm;
    }

    public void setMgfAlgorithm(String mgfAlgorithm) {
        this.mgfAlgorithm = mgfAlgorithm;
    }

    public int getSaltLength() {
        return saltLength;
    }

    public void setSaltLength(int saltLength) {
        this.saltLength = saltLength;
    }

    public boolean isNonDecorateSignature() {
        return nonDecorateSignature;
    }

    public void setNonDecorateSignature(boolean nonDecorateSignature) {
        this.nonDecorateSignature = nonDecorateSignature;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = group;
    }

    public int getServiceId() {
        return serviceId;
    }

    public void setServiceId(int serviceId) {
        this.serviceId = serviceId;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getAuth() {
        return auth;
    }

    public void setAuth(String auth) {
        this.auth = auth;
    }
}
