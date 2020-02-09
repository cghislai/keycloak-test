package com.charlyghislain.keycloaktest.backend.rest;

import com.charlyghislain.keycloaktest.backend.config.Roles;
import org.eclipse.microprofile.auth.LoginConfig;

import javax.annotation.security.DeclareRoles;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

@ApplicationPath("/")
@DeclareRoles({Roles.ADMIN, Roles.ROLEA, Roles.ROLEB})
@LoginConfig(authMethod = "MP-JWT", realmName = "test-realm")
public class BackendApplication extends Application {
}
