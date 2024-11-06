package net.jsign.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jsign.model.CertificateDTO;
import net.jsign.model.SignatureResponse;

public class CertificateUtil {


    public CertificateDTO getCertificate(String jsonString) {
        try{
            // Initialize Jackson ObjectMapper
            ObjectMapper objectMapper = new ObjectMapper();
            //Convert JSON String to Java Object
            CertificateDTO certificateDTO = objectMapper.readValue(jsonString, CertificateDTO.class);
            return certificateDTO;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public SignatureResponse getSignature(String jsonString) {
        try{
            // Initialize Jackson ObjectMapper
            ObjectMapper objectMapper = new ObjectMapper();
            //Convert JSON String to Java Object
            SignatureResponse signature = objectMapper.readValue(jsonString, SignatureResponse.class);
            return signature;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

}
