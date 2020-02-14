package com.charlyghislain.keycloak.beid.credential;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class BeIdCredentialModel extends CredentialModel {
    public static final String TYPE = "BELGIAN_EID";

    private BeidCertificateSecret credientialSecret;

    private BeIdCredentialModel(BeidCertificateSecret certificateSecret) {
        this.credientialSecret = certificateSecret;
    }

    public static BeIdCredentialModel createFromCertificate(BeidCertificateSecret certificateSecret) {
        BeIdCredentialModel beIdCredentialModel = new BeIdCredentialModel(certificateSecret);
        beIdCredentialModel.fillPrivateFields();
        return beIdCredentialModel;
    }

    public static BeIdCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        try {
            BeidCertificateSecret beidCertificateSecret = JsonSerialization.readValue(credentialModel.getSecretData(), BeidCertificateSecret.class);
            BeIdCredentialModel beIdCredentialModel = new BeIdCredentialModel(beidCertificateSecret);
            beIdCredentialModel.setUserLabel(credentialModel.getUserLabel());
            beIdCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
            beIdCredentialModel.setType(TYPE);
            beIdCredentialModel.setId(credentialModel.getId());
            beIdCredentialModel.setSecretData(credentialModel.getSecretData());
            beIdCredentialModel.setCredentialData(credentialModel.getCredentialData());
            return beIdCredentialModel;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }


    private void fillPrivateFields() {
        try {
            setSecretData(JsonSerialization.writeValueAsString(credientialSecret));
            setType(TYPE);
            setCreatedDate(Time.currentTimeMillis());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
