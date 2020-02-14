package com.charlyghislain.keycloak.beid.credential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class BeidCertificateSecret {

    private final String ssin;
    private final String countryCode;
    private final String certName;
    private final String surname;
    private final String givenNames;
    private final String publicKeyHash;
    private final String notAfterIsoDateString;


    @JsonCreator
    public BeidCertificateSecret(
            @JsonProperty("ssin") String ssin,
            @JsonProperty("country") String countryCode,
            @JsonProperty("certName") String certName,
            @JsonProperty("lastName") String surname,
            @JsonProperty("givenNames") String givenNames,
            @JsonProperty("publicKeyHash") String publicKeyHash,
            @JsonProperty("notAfter") String notAfterIsoDateString
    ) {
        this.ssin = ssin;
        this.countryCode = countryCode;
        this.certName = certName;
        this.surname = surname;
        this.givenNames = givenNames;
        this.publicKeyHash = publicKeyHash;
        this.notAfterIsoDateString = notAfterIsoDateString;
    }

    public String getSsin() {
        return ssin;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public String getCertName() {
        return certName;
    }

    public String getSurname() {
        return surname;
    }

    public String getGivenNames() {
        return givenNames;
    }

    public String getPublicKeyHash() {
        return publicKeyHash;
    }

    public String getNotAfter() {
        return notAfterIsoDateString;
    }
}
