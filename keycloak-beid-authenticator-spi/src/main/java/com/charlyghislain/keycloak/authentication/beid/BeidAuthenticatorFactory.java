package com.charlyghislain.keycloak.authentication.beid;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;

public class BeidAuthenticatorFactory extends AbstractX509ClientCertificateAuthenticatorFactory {

    public static final String PROVIDER_ID = "auth-beid-ssin-names-form";
    public static final BeidAuthenticator SINGLETON = new BeidAuthenticator();


    @Override
    public String getDisplayType() {
        return "Beid X509/Validate ssn or names";
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getHelpText() {
        return "Validate certificate ssin (if custom parameter set in config), or surname+first given name, from the id card authentication client certificate";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
