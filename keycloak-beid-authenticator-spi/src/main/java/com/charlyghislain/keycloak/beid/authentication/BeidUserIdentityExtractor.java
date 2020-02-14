package com.charlyghislain.keycloak.beid.authentication;

import com.charlyghislain.keycloak.beid.config.BeidAuthenticatorConfig;
import com.charlyghislain.keycloak.beid.credential.BeidCertificateSecret;
import org.keycloak.authentication.authenticators.x509.UserIdentityExtractor;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class BeidUserIdentityExtractor extends UserIdentityExtractor {

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


        Matcher serialNumberMatcher = BeidAuthenticatorConfig.SSIN_PATTERN.matcher(serialNumber);
        if (!serialNumberMatcher.matches()) {
            return Optional.empty();
        }

        String b64PublicKeyHash = hashPublicKey(cert);

        Date notAfter = cert.getNotAfter();
        Instant notAfterInstant = notAfter.toInstant();
        String notAfterIsoDateString = LocalDate.ofInstant(notAfterInstant, ZoneId.systemDefault())
                .format(DateTimeFormatter.ISO_DATE);

        BeidCertificateSecret userIdentity = new BeidCertificateSecret(
                serialNumber, country, certName, surname, givenName, b64PublicKeyHash, notAfterIsoDateString
        );
        return Optional.of(userIdentity);
    }

    private String hashPublicKey(X509Certificate cert) {
        try {
            PublicKey publicKey = cert.getPublicKey();
            byte[] publicKeyBytes = publicKey.getEncoded();
            MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
            byte[] sha1DigestBytes = sha1Digest.digest(publicKeyBytes);
            return Base64.getEncoder().encodeToString(sha1DigestBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
