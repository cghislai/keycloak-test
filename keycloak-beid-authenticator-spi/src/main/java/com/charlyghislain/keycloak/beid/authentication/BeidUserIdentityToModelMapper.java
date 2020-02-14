package com.charlyghislain.keycloak.beid.authentication;

import com.charlyghislain.keycloak.beid.credential.BeidCertificateSecret;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.x509.UserIdentityToModelMapper;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BeidUserIdentityToModelMapper extends UserIdentityToModelMapper {

    private final String ssinAttributeName;

    public BeidUserIdentityToModelMapper(X509AuthenticatorConfigModel config) {
        this.ssinAttributeName = config.getCustomAttributeName();
    }

    @Override
    public UserModel find(AuthenticationFlowContext context, Object userIdentity) throws Exception {
        KeycloakSession session = context.getSession();
        if (userIdentity == null || !BeidCertificateSecret.class.isAssignableFrom(userIdentity.getClass())) {
            return null;
        }
        BeidCertificateSecret beidCertificateSecret = (BeidCertificateSecret) userIdentity;

        List<UserModel> users;
        if (ssinAttributeName != null && !ssinAttributeName.isBlank()) {
            // Match by ssin
            String ssin = beidCertificateSecret.getSsin();
            users = session.users().searchForUserByUserAttribute(ssinAttributeName, ssin, context.getRealm());
        } else {
            // Match by names
            String surname = beidCertificateSecret.getSurname();
            String givenNames = beidCertificateSecret.getGivenNames();
            String givenName = Arrays.stream(givenNames.split(" "))
                    .findFirst()
                    .orElse("");

            Map<String, String> userAttributes = new HashMap<>();
            userAttributes.put("lastName", surname);
            userAttributes.put("firstName", givenName);
            users = session.users().searchForUser(userAttributes, context.getRealm());
        }

        if (users.size() > 1) {
            throw new ModelDuplicateException();
        } else if (users.size() == 1) {
            return users.get(0);
        } else {
            return null;
        }

    }
}
