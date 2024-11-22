package net.jsign.service;

import net.jsign.DigestAlgorithm;
import net.jsign.exception.FailedCertificateExtractionException;
import net.jsign.exception.NoEndpointSpecifiedException;
import net.jsign.exception.SignRequestFailedException;
import net.jsign.exception.NotABooleanValueException;
import net.jsign.exception.NotACorrectIntegerValueException;
import net.jsign.jca.CustomProviderServiceInterface;
import net.jsign.jca.SigningService;
import net.jsign.jca.SigningServicePrivateKey;
import net.jsign.model.CertificateDTO;
import net.jsign.model.Chain;
import net.jsign.model.SignatureResponse;
import net.jsign.util.CertificateService;
import net.jsign.util.ParameterChecker;

import java.io.ByteArrayInputStream;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;


/**
 * Custom signing service implementation for a mock API.
 */
public class ExternalProviderService implements SigningService, CustomProviderServiceInterface {
    CertificateService certificateService;
    ParameterChecker checker = new ParameterChecker();
    private final Logger logger = Logger.getLogger(ExternalProviderService.class.getName());

    String parameters;
    private final String alias = "default";
    private final List<Certificate> certificates = new ArrayList<>();
    private String endpoint;
    String signAlgorithm;
    String mgfAlgorithm;
    int saltLength;
    boolean nonDecorateSignature;
    String group;
    String serviceId;
    String user;
    String auth;

    public ExternalProviderService(String keystore, String parameters){
        HttpClient client = HttpClient.newHttpClient();
        this.certificateService = new CertificateService(client);
        this.init(keystore, parameters);
    }

    // For testing purposes
    public ExternalProviderService(String keystore, String parameters, CertificateService certificateService){
        this.certificateService = certificateService;
        this.init(keystore, parameters);
    }

    /**
     * Creates a new CustomProviderService.
     * @param endpoint
     * @param signAlgorithm
     * @param mgfAlgorithm
     * @param saltLength
     * @param nonDecorateSignature
     * @param group
     * @param serviceId
     * @param user
     * @param auth
     * @throws NoEndpointSpecifiedException
     */
    public ExternalProviderService(String endpoint,
                                   String signAlgorithm,
                                   String mgfAlgorithm,
                                   int saltLength,
                                   boolean nonDecorateSignature,
                                   String group,
                                   String serviceId,
                                   String user,
                                   String auth) {
        HttpClient client = HttpClient.newHttpClient();
        certificateService = new CertificateService(client);
        logger.info("Initializing CustomProviderService with endpoint: " + endpoint);
        logger.info("Setting endpoint to: " + endpoint);
        this.endpoint = endpoint;

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
        logger.info("auth was successfully set");
    }

    // For testing purposes
    public ExternalProviderService(CertificateService certificateService,
                                   String endpoint,
                                   String signAlgorithm,
                                   String mgfAlgorithm,
                                   int saltLength,
                                   boolean nonDecorateSignature,
                                   String group,
                                   String serviceId,
                                   String user,
                                   String auth) {
        this.certificateService = certificateService;
        logger.info("Initializing CustomProviderService with endpoint: " + endpoint);
        logger.info("Setting endpoint to: " + endpoint);
        this.endpoint = endpoint;

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
        logger.info("auth was successfully set");
    }

    public ExternalProviderService(CertificateService certificateService){
        this.certificateService = certificateService;

    }

    @Override
    public String getName() {
        return "CustomProviderService";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        logger.info("Retrieving aliases for KeyStore");
        return Collections.singletonList(alias);
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
            logger.severe("Thrown exception: " + e.getClass());
            logger.severe("Exception message: " + e.getMessage());
            throw new KeyStoreException("Failed to get certificate from server for user with id: " + user, e);
        }
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        try{
            logger.info("Skipping this method");
            return new SigningServicePrivateKey("server-key-id", "RSA", this);
        } catch (Exception e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch DigiCert ONE private key for the certificate '" + alias + "'").initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        logger.info("Signing data with certificate");
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(signAlgorithm.substring(0, signAlgorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);
        try {
            SignatureResponse signature = certificateService.getSignature(endpoint, data, signAlgorithm, mgfAlgorithm, saltLength, nonDecorateSignature, group, serviceId, user, auth);
            logger.info("Checking if signature was successful");
            if (signature.getSignReturnCode() == "FAILED") {
                logger.info("Failed to sign data with certificate!");
                String errorMessage = signature.getErrorMessage();
                logger.info("An error occured while creating the signature on the server site: " + signature.getErrorMessage());
                throw new SignRequestFailedException(errorMessage);
            } else {
                logger.info("Successfully signed data with certificate");
                return Base64.getDecoder().decode(signature.getSignedHash());
            }
        }catch(Exception e){
            logger.severe("Failed to sign data with certificate");
            logger.severe("Thrown exception: " + e.getClass());
            logger.severe("Exception message: " + e.getMessage());
            throw new GeneralSecurityException("Failed to sign data with certificate", e);
        }
    }

    @Override
    public void validate(String keystore, String parameters) {
        logger.info("Validating ExternalProviderService");
        logger.info("Validating keystore parameter");
        if (keystore == null || keystore.isEmpty()) {
            logger.severe("No endpoint specified for the signing service in the keystore parameter!");
            throw new IllegalArgumentException(new NoEndpointSpecifiedException("No endpoint specified for the signing service in the keystore parameter!"));
        }
        logger.info("Validating storepass parameter");
        if (parameters == null || parameters.split("\\|").length != 8 || checker.checkIfStringisEmpty(parameters.split("\\|"))) {
            logger.severe("storepass " + parameters + " must specify the needed Signing Service parameters: <signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>");
            logger.severe("storepass: " + parameters);
            throw new IllegalArgumentException("storepass " + parameters + " must specify the needed Signing Service parameters: <signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>");
        }

        String[] elements = parameters.split("\\|");
        logger.info("Validating signature algorithm parameter");
        boolean nonDecorateSignature;
        int saltLength;
        logger.info("Verifying the values of non decorate signature parameters");
        if(checker.checkIfBoolean(elements[3])) {
            nonDecorateSignature = Boolean.parseBoolean(elements[3]);
        }else {
            logger.severe("The value of non decorate signature is not a boolean value");
            throw new IllegalArgumentException(new NotABooleanValueException("The value of non decorate signature is not a boolean value"));
        }
        logger.info("Verifying the values of salt length parameters");
        if(checker.checkIfInteger(elements[2])) {
            saltLength = Integer.parseInt(elements[2]);
        }
        else{
            logger.severe("The value of salt length is not an integer value");
            throw new IllegalArgumentException(new NotACorrectIntegerValueException("The value of salt length is not an integer value"));
        }
    }

    @Override
    public void init(String keystore, String parameters){
        logger.info("Initializing ExternalProviderService");
        try{
            validate(keystore, parameters);
        }catch (Exception e){
            logger.severe("Failed to validate ExternalProviderService parameters: " + e.getMessage());
            throw new RuntimeException(e);
        }
        String[] elements = parameters.split("\\|");
        logger.info("Initializing CustomProviderService with endpoint: " + keystore);
        logger.info("Setting endpoint to: " + keystore);
        this.setEndpoint(keystore);

        logger.info("Setting sign algorithm to: " + elements[0]);
        this.setSignAlgorithm(elements[0]);
        logger.info("Setting mask generation function to: " +  elements[1]);
        this.setMgfAlgorithm(elements[1]);
        logger.info("Setting salt length to: " + elements[2]);
        this.setSaltLength(Integer.parseInt(elements[2]));
        logger.info("Setting non decorate signature to: " + elements[3]);
        this.setNonDecorateSignature(Boolean.parseBoolean(elements[3]));
        logger.info("Setting group to: " + elements[4]);
        this.setGroup(elements[4]);
        logger.info("Setting service id to: " + elements[5]);
        this.setServiceId(elements[5]);
        logger.info("Setting user to: " + elements[6]);
        this.setUser(elements[6]);
        this.setAuth(elements[7]);
        logger.info("auth was successfully set");
        //return this;
    }

    public CertificateService getCertificateService() {
        return certificateService;
    }

    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    public ParameterChecker getChecker() {
        return checker;
    }

    public void setChecker(ParameterChecker checker) {
        this.checker = checker;
    }

    public Logger getLogger() {
        return logger;
    }

    public String getParameters() {
        return parameters;
    }

    public void setParameters(String parameters) {
        this.parameters = parameters;
    }

    public String getAlias() {
        return alias;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
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

    public String getServiceId() {
        return serviceId;
    }

    public void setServiceId(String serviceId) {
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