package net.jsign.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jsign.model.CertificateDTO;
import net.jsign.model.CertificateList;
import net.jsign.model.Signature;

public class CertificateUtil {

    public CertificateList getCertificates(String jsonString) {
       try{
           // Initialize Jackson ObjectMapper
           ObjectMapper objectMapper = new ObjectMapper();
           //Convert JSON String to Java Object
           CertificateList certificateList = objectMapper.readValue(jsonString, CertificateList.class);
           return certificateList;
       }catch (Exception e){
           e.printStackTrace();
       }
        return null;
    }

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

    public Signature getSignature(String jsonString) {
        try{
            // Initialize Jackson ObjectMapper
            ObjectMapper objectMapper = new ObjectMapper();
            //Convert JSON String to Java Object
            Signature signature = objectMapper.readValue(jsonString, Signature.class);
            return signature;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

}
