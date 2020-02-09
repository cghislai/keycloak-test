package com.charlyghislain.keycloaktest.backend.rest;

import com.charlyghislain.keycloaktest.backend.config.Roles;
import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import java.text.MessageFormat;

@Path("/hello")
public class HelloUser {

    @Inject
    private JsonWebToken callerPrincipal;
    @Context
    private SecurityContext securityContext;

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed(Roles.ROLEA)
    public String getHelloUser() {
        String subject = callerPrincipal.getSubject();
        String name = callerPrincipal.getName();
        String email = callerPrincipal.getClaim("email");
        String groups = String.join(",", callerPrincipal.getGroups());
        String message = MessageFormat.format("Hello, you are in groups {0}", groups);
        message += MessageFormat.format("\nSubject: {0}\nEmail: {1}\nPrincipal name: {2}", subject, email, name);
        return message;
    }
}
