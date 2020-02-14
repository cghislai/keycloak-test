package com.charlyghislain.keycloak.beid.registration;

import com.charlyghislain.keycloak.beid.config.BeidAuthenticatorConfig;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

import static java.util.Arrays.asList;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.CRL_RELATIVE_PATH;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.ENABLE_CRL;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.ENABLE_CRLDP;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.ENABLE_OCSP;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.OCSPRESPONDER_CERTIFICATE;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.OCSPRESPONDER_URI;
import static org.keycloak.provider.ProviderConfigProperty.BOOLEAN_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.MULTIVALUED_STRING_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.TEXT_TYPE;

public class BeidRegistrationReadEidFactory implements FormActionFactory {

    public static final String PROVIDER_ID = "beid-registration-read-eid";
    private final BeidRegistrationReadEid SINGLETON = new BeidRegistrationReadEid();


    @Override
    public String getDisplayType() {
        return "Belgian eid card reading";
    }


    @Override
    public String getHelpText() {
        return "Read the belgian ID card certificate, fill out first and last names and store additional user attributes.";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    protected static final List<ProviderConfigProperty> configProperties;

    static {
        ProviderConfigProperty certRequired = new ProviderConfigProperty();
        certRequired.setType(BOOLEAN_TYPE);
        certRequired.setName(BeidAuthenticatorConfig.BEID_CLIENT_CERT_ON_REGISTRATION_REQUIRED);
        certRequired.setDefaultValue(false);
        certRequired.setLabel("ID card certificate required");
        certRequired.setHelpText("Is the reading of the id card required");

        ProviderConfigProperty ssinUserAttribute = new ProviderConfigProperty();
        ssinUserAttribute.setType(STRING_TYPE);
        ssinUserAttribute.setName(BeidAuthenticatorConfig.BEID_SSIN_USER_ATTRIBUTE_NAME);
        ssinUserAttribute.setDefaultValue("ssin");
        ssinUserAttribute.setLabel("SSIN user attribute name");
        ssinUserAttribute.setHelpText("The user attribute in which to store the social security national number");

        ProviderConfigProperty pubKeyUserAttribute = new ProviderConfigProperty();
        pubKeyUserAttribute.setType(STRING_TYPE);
        pubKeyUserAttribute.setName(BeidAuthenticatorConfig.BEID_PUBLIC_KEY_USER_ATTRIBUTE_NAME);
        pubKeyUserAttribute.setDefaultValue("certPublicKey");
        pubKeyUserAttribute.setLabel("Public key user attribute name");
        pubKeyUserAttribute.setHelpText("The user attribute in which to store the id card public key hash");

        ProviderConfigProperty expiryUserAttribute = new ProviderConfigProperty();
        expiryUserAttribute.setType(STRING_TYPE);
        expiryUserAttribute.setName(BeidAuthenticatorConfig.BEID_CARD_EXPIRY_USER_ATTRIBUTE_NAME);
        expiryUserAttribute.setDefaultValue("certNotAfter");
        expiryUserAttribute.setLabel("Card expiry user attribute name");
        expiryUserAttribute.setHelpText("The user attribute in which to store the id card expiry date");

        ProviderConfigProperty crlCheckingEnabled = new ProviderConfigProperty();
        crlCheckingEnabled.setType(BOOLEAN_TYPE);
        crlCheckingEnabled.setName(ENABLE_CRL);
        crlCheckingEnabled.setHelpText("Enable Certificate Revocation Checking using CRL");
        crlCheckingEnabled.setLabel("CRL Checking Enabled");

        ProviderConfigProperty crlDPEnabled = new ProviderConfigProperty();
        crlDPEnabled.setType(BOOLEAN_TYPE);
        crlDPEnabled.setName(ENABLE_CRLDP);
        crlDPEnabled.setDefaultValue(false);
        crlDPEnabled.setLabel("Enable CRL Distribution Point to check certificate revocation status");
        crlDPEnabled.setHelpText("CRL Distribution Point is a starting point for CRL. If this is ON, then CRL checking will be done based on the CRL distribution points included" +
                " in the checked certificates. CDP is optional, but most PKI authorities include CDP in their certificates.");

        ProviderConfigProperty cRLRelativePath = new ProviderConfigProperty();
        cRLRelativePath.setType(MULTIVALUED_STRING_TYPE);
        cRLRelativePath.setName(CRL_RELATIVE_PATH);
        cRLRelativePath.setDefaultValue("crl.pem");
        cRLRelativePath.setLabel("CRL Path");
        cRLRelativePath.setHelpText("Applied just if CRL checking is ON and CRL Distribution point is OFF. It contains the URL (typically 'http' or 'ldap') " +
                "where the CRL is available. Alternatively it can contain the path to a CRL file that contains a list of revoked certificates. Paths are assumed to be relative to $jboss.server.config.dir. " +
                "Multiple CRLs can be included, however it can affect performance as the certificate will be checked against all listed CRLs."
        );

        ProviderConfigProperty oCspCheckingEnabled = new ProviderConfigProperty();
        oCspCheckingEnabled.setType(BOOLEAN_TYPE);
        oCspCheckingEnabled.setName(ENABLE_OCSP);
        oCspCheckingEnabled.setHelpText("Enable Certificate Revocation Checking using OCSP");
        oCspCheckingEnabled.setLabel("OCSP Checking Enabled");

        ProviderConfigProperty ocspResponderUri = new ProviderConfigProperty();
        ocspResponderUri.setType(STRING_TYPE);
        ocspResponderUri.setName(OCSPRESPONDER_URI);
        ocspResponderUri.setLabel("OCSP Responder Uri");
        ocspResponderUri.setHelpText("Clients use OCSP Responder Uri to check certificate revocation status.");

        ProviderConfigProperty ocspResponderCert = new ProviderConfigProperty();
        ocspResponderCert.setType(TEXT_TYPE);
        ocspResponderCert.setName(OCSPRESPONDER_CERTIFICATE);
        ocspResponderCert.setLabel("OCSP Responder Certificate");
        ocspResponderCert.setHelpText("Optional certificate used by the responder to sign the responses. The certificate should be in PEM format without BEGIN and END tags. It is only used if the OCSP Responder URI is set. By default, the certificate of the OCSP responder is that of the issuer of the certificate being validated or one with the OCSPSigning extension and also issued by the same CA. This option identifies the certificate of the OCSP responder when the defaults do not apply.");
//
//        ProviderConfigProperty keyUsage = new ProviderConfigProperty();
//        keyUsage.setType(STRING_TYPE);
//        keyUsage.setName(CERTIFICATE_KEY_USAGE);
//        keyUsage.setLabel("Validate Key Usage");
//        keyUsage.setHelpText("Validates that the purpose of the key contained in the certificate (encipherment, signature, etc.) matches its intended purpose. Leaving the field blank will disable Key Usage validation. For example, 'digitalSignature, keyEncipherment' will check if the digitalSignature and keyEncipherment bits (bit 0 and bit 2 respectively) are set in certificate's X509 Key Usage extension. See RFC 5280 for a detailed definition of X509 Key Usage extension.");
//
//        ProviderConfigProperty extendedKeyUsage = new ProviderConfigProperty();
//        extendedKeyUsage.setType(STRING_TYPE);
//        extendedKeyUsage.setName(CERTIFICATE_EXTENDED_KEY_USAGE);
//        extendedKeyUsage.setLabel("Validate Extended Key Usage");
//        extendedKeyUsage.setHelpText("Validates the extended purposes of the certificate's key using certificate's Extended Key Usage extension. Leaving the field blank will disable Extended Key Usage validation. See RFC 5280 for a detailed definition of X509 Extended Key Usage extension.");

        configProperties = asList(
                certRequired,
                ssinUserAttribute,
                pubKeyUserAttribute,
                expiryUserAttribute,
                crlCheckingEnabled,
                crlDPEnabled,
                cRLRelativePath,
                oCspCheckingEnabled,
                ocspResponderUri,
                ocspResponderCert
//                keyUsage,
//                extendedKeyUsage
        );
    }


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;

    }

    @Override
    public String getReferenceCategory() {
        return null;
    }


    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public FormAction create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
