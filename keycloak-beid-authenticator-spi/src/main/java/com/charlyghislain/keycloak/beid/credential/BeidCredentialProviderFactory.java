package com.charlyghislain.keycloak.beid.credential;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class BeidCredentialProviderFactory implements CredentialProviderFactory<BeidCredentialProvider> {
    public static final String PROVIDER_ID = "beid-credential";

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new BeidCredentialProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
