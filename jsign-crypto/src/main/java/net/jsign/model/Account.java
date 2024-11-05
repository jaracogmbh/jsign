package net.jsign.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

//@JsonIgnoreProperties(ignoreUnknown = true)
public class Account {
    String id;
    String name;
    boolean cert_central_integration_allowed;
    boolean dynamic_test_keypair_allowed;
    boolean gpg_enabled;
    boolean is_csr_gen_enabled;


    public Account() {
    }

    public Account(String id, String name, boolean cert_central_integration_allowed, boolean dynamic_test_keypair_allowed, boolean gpg_enabled, boolean is_csr_gen_enabled) {
        this.id = id;
        this.name = name;
        this.cert_central_integration_allowed = cert_central_integration_allowed;
        this.dynamic_test_keypair_allowed = dynamic_test_keypair_allowed;
        this.gpg_enabled = gpg_enabled;
        this.is_csr_gen_enabled = is_csr_gen_enabled;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isCert_central_integration_allowed() {
        return cert_central_integration_allowed;
    }

    public void setCert_central_integration_allowed(boolean cert_central_integration_allowed) {
        this.cert_central_integration_allowed = cert_central_integration_allowed;
    }

    public boolean isDynamic_test_keypair_allowed() {
        return dynamic_test_keypair_allowed;
    }

    public void setDynamic_test_keypair_allowed(boolean dynamic_test_keypair_allowed) {
        this.dynamic_test_keypair_allowed = dynamic_test_keypair_allowed;
    }

    public boolean isGpg_enabled() {
        return gpg_enabled;
    }

    public void setGpg_enabled(boolean gpg_enabled) {
        this.gpg_enabled = gpg_enabled;
    }

    public boolean isIs_csr_gen_enabled() {
        return is_csr_gen_enabled;
    }

    public void setIs_csr_gen_enabled(boolean is_csr_gen_enabled) {
        this.is_csr_gen_enabled = is_csr_gen_enabled;
    }


}


