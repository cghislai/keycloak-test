package com.charlyghislain.keycloak.beid.credential;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.UserCredentialStore;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class BeidCredentialProvider implements CredentialProvider<BeIdCredentialModel> {

    protected KeycloakSession session;

    public BeidCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return BeIdCredentialModel.TYPE;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, BeIdCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        return getCredentialStore().createCredential(realm, user, credentialModel);
    }

    @Override
    public void deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        getCredentialStore().removeStoredCredential(realm, user, credentialId);
    }

    @Override
    public BeIdCredentialModel getCredentialFromModel(CredentialModel model) {
        return BeIdCredentialModel.createFromCredentialModel(model);
    }

    private UserCredentialStore getCredentialStore() {
        return session.userCredentialManager();
    }
}
