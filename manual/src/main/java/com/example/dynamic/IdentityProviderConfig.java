package com.example.dynamic;

import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

/**
 * Replace this with a JPA object
 */
public class IdentityProviderConfig {

    public final int id;
    public final AuthorizationCodeResourceDetails codeResourceDetails;
    public final ResourceServerProperties resourceServerProperties;

    public IdentityProviderConfig(int id, AuthorizationCodeResourceDetails codeResourceDetails, ResourceServerProperties resourceServerProperties) {
        this.id = id;
        this.codeResourceDetails = codeResourceDetails;
        this.resourceServerProperties = resourceServerProperties;
    }
}
