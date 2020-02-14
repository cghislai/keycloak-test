package com.charlyghislain.keycloak.beid.config;

import java.util.regex.Pattern;

public class BeidAuthenticatorConfig {

    public final static String BEID_CLIENT_CERT_ON_REGISTRATION_REQUIRED = "beidRequired";
    public final static String BEID_SSIN_USER_ATTRIBUTE_NAME = "beidSsinUserAttributeName";
    public final static String BEID_PUBLIC_KEY_USER_ATTRIBUTE_NAME = "beidPublicKeyUserAttributeName";
    public final static String BEID_CARD_EXPIRY_USER_ATTRIBUTE_NAME = "beidCardExpiryUserAttributeName";

    public static final Pattern SSIN_PATTERN = Pattern.compile("[0-9]{11}");

}
