package com.charlyghislain.keycloak.beid.registration;

import com.charlyghislain.keycloak.beid.authentication.BeidUserIdentityExtractor;
import com.charlyghislain.keycloak.beid.config.BeidAuthenticatorConfig;
import com.charlyghislain.keycloak.beid.config.BeidFormConfig;
import com.charlyghislain.keycloak.beid.config.BeidMessages;
import com.charlyghislain.keycloak.beid.credential.BeidCertificateSecret;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.authenticators.x509.CertificateValidator;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.validation.Validation;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;

public class BeidRegistrationReadEid implements FormAction {

    protected static ServicesLogger logger = ServicesLogger.LOGGER;

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        if (authenticatorConfig == null || authenticatorConfig.getConfig() == null
                || authenticatorConfig.getConfig().get(BeidAuthenticatorConfig.BEID_CLIENT_CERT_ON_REGISTRATION_REQUIRED) == null) {
            form.addError(new FormMessage(null, BeidMessages.BEID_NOT_CONFIGURED));
            return;
        }

        readCert(context, form);
    }


    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();

        String requiredConfigValue = authenticatorConfig.getConfig().get(BeidAuthenticatorConfig.BEID_CLIENT_CERT_ON_REGISTRATION_REQUIRED);
        boolean requiredValue = Boolean.parseBoolean(requiredConfigValue);

        if (!requiredValue) {
            context.success();
        }

        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        String ssinValue = authenticationSession.getAuthNote(BeidFormConfig.FORM_ATTRIBUTE_SSIN);
        List<FormMessage> errors = new ArrayList<>();
        boolean success = false;

        Boolean ssinValid = Optional.ofNullable(ssinValue)
                .filter(s -> !s.isBlank())
                .map(BeidAuthenticatorConfig.SSIN_PATTERN::matcher)
                .map(Matcher::matches)
                .orElse(false);
        if (ssinValid) {
            success = true;
        }

        if (success) {
            context.success();
        } else {
            errors.add(new FormMessage(null, BeidMessages.BEID_MISSING_CERT_ERROR));
            formData.remove(BeidFormConfig.FORM_ATTRIBUTE_SSIN);
            context.validationError(formData, errors);
            return;
        }
    }

    @Override
    public void success(FormContext context) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        Map<String, String> config = authenticatorConfig.getConfig();
        String ssinAttributeName = config.getOrDefault(BeidAuthenticatorConfig.BEID_SSIN_USER_ATTRIBUTE_NAME, "ssin");
        String pubKeyAttributeName = config.getOrDefault(BeidAuthenticatorConfig.BEID_PUBLIC_KEY_USER_ATTRIBUTE_NAME, "certPublicKey");
        String notAfterAttributeName = config.getOrDefault(BeidAuthenticatorConfig.BEID_CARD_EXPIRY_USER_ATTRIBUTE_NAME, "certNotAfter");

        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        String ssin = authenticationSession.getAuthNote(BeidFormConfig.FORM_ATTRIBUTE_SSIN);
        String publicKey = authenticationSession.getAuthNote(BeidFormConfig.FORM_ATTRIBUTE_PUBLIC_KEY);
        String notAfter = authenticationSession.getAuthNote(BeidFormConfig.FORM_ATTRIBUTE_NOT_AFTER);

        UserModel user = context.getUser();
        user.setSingleAttribute(ssinAttributeName, ssin);
        user.setSingleAttribute(pubKeyAttributeName, publicKey);
        user.setSingleAttribute(notAfterAttributeName, notAfter);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }


    private void readCert(FormContext context, LoginFormsProvider form) {
        X509Certificate[] certs = getCertificateChain(context);
        if (certs == null || certs.length == 0) {
            // No x509 client cert, fall through and
            // continue processing the rest of the authentication flow
            logger.debug("[X509ClientCertificateAuthenticator:authenticate] x509 client certificate is not available for mutual SSL.");
            return;
        }

        saveX509CertificateAuditDataToAuthSession(context, certs[0]);
        recordX509CertificateAuditDataViaContextEvent(context);

        X509AuthenticatorConfigModel config = null;
        if (context.getAuthenticatorConfig() != null && context.getAuthenticatorConfig().getConfig() != null) {
            config = new X509AuthenticatorConfigModel(context.getAuthenticatorConfig());
        }
        if (config == null) {
            logger.warn("[X509ClientCertificateAuthenticator:authenticate] x509 Client Certificate Authentication configuration is not available.");
            return;
        }

        // Validate X509 client certificate
        try {
            CertificateValidator.CertificateValidatorBuilder builder = certificateValidationParameters(context.getSession(), config);
            CertificateValidator validator = builder.build(certs);
            validator.checkRevocationStatus()
                    .validateKeyUsage()
                    .validateExtendedKeyUsage();
//                        .validateTimestamps(config.isCertValidationEnabled());
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            // TODO use specific locale to load error messages
            String errorMessage = "Certificate validation's failed.";
            // TODO is calling form().setErrors enough to show errors on login screen?
//            context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
//                    errorMessage, e.getMessage()));
//            context.attempted();
            return;
        }

        BeidUserIdentityExtractor beidUserIdentityExtractor = new BeidUserIdentityExtractor();
        Object userIdentity = beidUserIdentityExtractor.extractUserIdentity(certs);
        if (userIdentity == null || !BeidCertificateSecret.class.isAssignableFrom(userIdentity.getClass())) {
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            logger.warnf("[X509ClientCertificateAuthenticator:authenticate] Unable to extract user identity from certificate.");
            // TODO use specific locale to load error messages
            String errorMessage = "Unable to extract user identity from specified certificate";
            // TODO is calling form().setErrors enough to show errors on login screen?
//            context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
//            context.attempted();
            return;
        }

        BeidCertificateSecret beidCertificateSecret = (BeidCertificateSecret) userIdentity;

        form.setAttribute(BeidFormConfig.FORM_ATTRIBUTE_FIRST_NAME_DISABLED, true);
        form.setAttribute(BeidFormConfig.FORM_ATTRIBUTE_LAST_NAME_DISABLED, true);

        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        authenticationSession.setAuthNote(BeidFormConfig.FORM_ATTRIBUTE_SSIN, beidCertificateSecret.getSsin());
        authenticationSession.setAuthNote(BeidFormConfig.FORM_ATTRIBUTE_PUBLIC_KEY, beidCertificateSecret.getPublicKeyHash());
        authenticationSession.setAuthNote(BeidFormConfig.FORM_ATTRIBUTE_NOT_AFTER, beidCertificateSecret.getNotAfter());

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle(Validation.FIELD_FIRST_NAME, beidCertificateSecret.getGivenNames());
        formData.putSingle(Validation.FIELD_LAST_NAME, beidCertificateSecret.getSurname());
        form.setFormData(formData);
    }

    private CertificateValidator.CertificateValidatorBuilder certificateValidationParameters(KeycloakSession session, X509AuthenticatorConfigModel config) {
        CertificateValidator.CertificateValidatorBuilder builder = new CertificateValidator.CertificateValidatorBuilder();
        return builder
                .session(session)
//                .keyUsage()
//                .parse(config.getKeyUsage())
//                .extendedKeyUsage()
//                .parse(config.getExtendedKeyUsage())
                .revocation()
                .cRLEnabled(config.getCRLEnabled())
                .cRLDPEnabled(config.getCRLDistributionPointEnabled())
                .cRLrelativePath(config.getCRLRelativePath())
                .oCSPEnabled(config.getOCSPEnabled())
                .oCSPResponseCertificate(config.getOCSPResponderCertificate())
                .oCSPResponderURI(config.getOCSPResponder());
    }

    protected X509Certificate[] getCertificateChain(FormContext context) {
        try {
            // Get a x509 client certificate
            X509ClientCertificateLookup provider = context.getSession().getProvider(X509ClientCertificateLookup.class);
            if (provider == null) {
                logger.errorv("\"{0}\" Spi is not available, did you forget to update the configuration?",
                        X509ClientCertificateLookup.class);
                return null;
            }

            X509Certificate[] certs = provider.getCertificateChain(context.getHttpRequest());

            if (certs != null) {
                for (X509Certificate cert : certs) {
                    logger.tracev("\"{0}\"", cert.getSubjectDN().getName());
                }
            }

            return certs;
        } catch (GeneralSecurityException e) {
            logger.error(e.getMessage(), e);
        }
        return null;
    }

    // Saving some notes for audit to authSession as the event may not be necessarily triggered in this HTTP request where the certificate was parsed
    // For example if there is confirmation page enabled, it will be in the additional request
    protected void saveX509CertificateAuditDataToAuthSession(FormContext context,
                                                             X509Certificate cert) {
        context.getAuthenticationSession().setAuthNote(Details.X509_CERTIFICATE_SERIAL_NUMBER, cert.getSerialNumber().toString());
        context.getAuthenticationSession().setAuthNote(Details.X509_CERTIFICATE_SUBJECT_DISTINGUISHED_NAME, cert.getSubjectDN().toString());
        context.getAuthenticationSession().setAuthNote(Details.X509_CERTIFICATE_ISSUER_DISTINGUISHED_NAME, cert.getIssuerDN().toString());
    }

    protected void recordX509CertificateAuditDataViaContextEvent(FormContext context) {
        recordX509DetailFromAuthSessionToEvent(context, Details.X509_CERTIFICATE_SERIAL_NUMBER);
        recordX509DetailFromAuthSessionToEvent(context, Details.X509_CERTIFICATE_SUBJECT_DISTINGUISHED_NAME);
        recordX509DetailFromAuthSessionToEvent(context, Details.X509_CERTIFICATE_ISSUER_DISTINGUISHED_NAME);
    }


    private void recordX509DetailFromAuthSessionToEvent(FormContext context, String detailName) {
        String detailValue = context.getAuthenticationSession().getAuthNote(detailName);
        context.getEvent().detail(detailName, detailValue);
    }

}
