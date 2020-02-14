package com.charlyghislain.keycloak.authentication.beid;

import org.keycloak.authentication.authenticators.x509.UserIdentityExtractor;

import java.security.Principal;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class BeidUserIdentityExtractor extends UserIdentityExtractor {

    public static final Pattern SERIAL_NUMBER_PATTERN = Pattern.compile("[0-9]{11}");
    public static final String ATTRIBUTE_KEY_SERIALNUMBER = "SERIALNUMBER";
    public static final String ATTRIBUTE_KEY_COUNTRY = "C";
    public static final String ATTRIBUTE_KEY_CERT_NAME = "CN";
    public static final String ATTRIBUTE_KEY_SURNAME = "SURNAME";
    public static final String ATTRIBUTE_KEY_GIVEN_NAME = "GIVENNAME";

    @Override
    public Object extractUserIdentity(X509Certificate[] certs) {
        return Arrays.stream(certs)
                .map(this::extractUserIdentityFromCert)
                .flatMap(Optional::stream)
                .findAny()
                .orElse(null);
    }

    private Optional<Object> extractUserIdentityFromCert(X509Certificate cert) {
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            return Optional.empty();
        }
        // Check authentication key usage
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage == null || keyUsage.length < 1 || !keyUsage[0]) {
            return Optional.empty();
        }

        Principal subjectDNPrincipal = cert.getSubjectDN();
        String subjectDNName = subjectDNPrincipal.getName();


        Map<String, String> attributesMap = Arrays.stream(subjectDNName.split(","))
                .map(String::trim)
                .map(attribute -> attribute.split("="))
                .collect(Collectors.toMap(
                        parts -> parts[0],
                        parts -> parts[1]
                ));
        if (!attributesMap.containsKey(ATTRIBUTE_KEY_SERIALNUMBER)
                || !attributesMap.containsKey(ATTRIBUTE_KEY_COUNTRY)
                || !attributesMap.containsKey(ATTRIBUTE_KEY_CERT_NAME)
                || !attributesMap.containsKey(ATTRIBUTE_KEY_SURNAME)
                || !attributesMap.containsKey(ATTRIBUTE_KEY_GIVEN_NAME)
        ) {
            return Optional.empty();
        }

        String serialNumber = attributesMap.get(ATTRIBUTE_KEY_SERIALNUMBER);
        String country = attributesMap.get(ATTRIBUTE_KEY_COUNTRY);
        String surname = attributesMap.get(ATTRIBUTE_KEY_SURNAME);
        String certName = attributesMap.get(ATTRIBUTE_KEY_CERT_NAME);
        String givenName = attributesMap.get(ATTRIBUTE_KEY_GIVEN_NAME);


        Matcher serialNumberMatcher = SERIAL_NUMBER_PATTERN.matcher(serialNumber);
        if (!serialNumberMatcher.matches()) {
            return Optional.empty();
        }

        BeidUserIdentity userIdentity = new BeidUserIdentity(
                serialNumber, country, certName, surname, givenName
        );
        return Optional.of(userIdentity);
    }
}
