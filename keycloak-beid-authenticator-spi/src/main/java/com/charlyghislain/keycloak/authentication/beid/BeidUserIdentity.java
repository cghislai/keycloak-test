package com.charlyghislain.keycloak.authentication.beid;

public class BeidUserIdentity {

    private String ssin;
    private String countryCode;
    private String certName;
    private String surname;
    private String givenNames;

    public BeidUserIdentity() {
    }

    public BeidUserIdentity(String ssin, String countryCode, String certName, String surname, String givenNames) {
        this.ssin = ssin;
        this.countryCode = countryCode;
        this.certName = certName;
        this.surname = surname;
        this.givenNames = givenNames;
    }

    public String getSsin() {
        return ssin;
    }

    public void setSsin(String ssin) {
        this.ssin = ssin;
    }

    public String getCertName() {
        return certName;
    }

    public void setCertName(String certName) {
        this.certName = certName;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public String getGivenNames() {
        return givenNames;
    }

    public void setGivenNames(String givenNames) {
        this.givenNames = givenNames;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }
}
