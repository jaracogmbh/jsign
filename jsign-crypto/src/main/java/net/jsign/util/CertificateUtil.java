package net.jsign.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jsign.exception.JsonResponseIncorrectException;
import net.jsign.model.CertificateDTO;
import net.jsign.model.SignatureResponse;

import java.util.logging.Logger;

public class CertificateUtil {

    private final Logger logger = Logger.getLogger(CertificateUtil.class.getName());

    public CertificateDTO getCertificate(String jsonString) throws JsonResponseIncorrectException {
        logger.info("Transforming JSON to CertificateDTO");
        try{
            logger.info(jsonString);
            ObjectMapper objectMapper = new ObjectMapper();
            //Convert JSON String to Java Object
            CertificateDTO certificateDTO = objectMapper.readValue(jsonString, CertificateDTO.class);
            if(isCertificateEmpty(certificateDTO)){
                logger.severe("Certificate Response hat empty fields");
                throw new Exception("Certificate Response hat empty fields: " + certificateDTO.toString());
            }
            return certificateDTO;
        }catch (Exception e){
            logger.severe("Failed to transform JSON to CertificateDTO: " + e.getMessage());
            throw new JsonResponseIncorrectException(e.getMessage());
        }

    }

    public SignatureResponse getSignature(String jsonString) throws JsonResponseIncorrectException {
        try{
            // Initialize Jackson ObjectMapper
            ObjectMapper objectMapper = new ObjectMapper();
            //Convert JSON String to Java Object
            SignatureResponse signature = objectMapper.readValue(jsonString, SignatureResponse.class);
            if (isSignatureEmpty(signature)){
                logger.severe("Signature Response had empty fields");
                throw new Exception("Response had empty fields: " + signature.toString());
            }
            return signature;
        }catch (Exception e){
            logger.severe("Failed to transform JSON to SignatureResponse: " + e.getMessage());
            throw new JsonResponseIncorrectException(e.getMessage());
        }

    }

    public boolean isCertificateEmpty(CertificateDTO certificateDTO){
        return certificateDTO == null || certificateDTO.getCert() == null || certificateDTO.getCert().isEmpty() || certificateDTO.getChain() == null || certificateDTO.getChain().isEmpty() || certificateDTO.getId() == null || certificateDTO.getId().isEmpty();
    }

    public boolean isSignatureEmpty(SignatureResponse signatureResponse){
        return signatureResponse == null || signatureResponse.getSignReturnCode() == null ||
                signatureResponse.getCertificateId() == null || signatureResponse.getCertificateId().isEmpty() ||
                signatureResponse.getSignCertificate() == null || signatureResponse.getSignCertificate().isEmpty() ||
                signatureResponse.getSignedHash() == null || signatureResponse.getSignedHash().isEmpty() ||
                signatureResponse.getSignTime() == null || signatureResponse.getValidUntil() == null ||
                signatureResponse.getValidUntil().isEmpty();
    }

}
