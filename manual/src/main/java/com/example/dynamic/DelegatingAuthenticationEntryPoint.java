package com.example.dynamic;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

/**
 * {@link AuthenticationEntryPoint} that considers if there's a single identity provider
 * then just redirect to it automatically. If there's multiple, force the user to go to the login
 * page so we can get more context around the user.
 */
class DelegatingAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final IdentityProviderService identityProviderService;

    DelegatingAuthenticationEntryPoint(IdentityProviderService identityProviderService) {
        this.identityProviderService = identityProviderService;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        AuthenticationEntryPoint delegate;
        Set<IdentityProviderConfig> identityProviderConfigs = this.identityProviderService.list();

        // Single provider = redirect to it automatically, assuming OAuth here but if LDAP was also an identity
        // provider you would want to check for it
        if (identityProviderConfigs.size() == 1) {
            delegate = new LoginUrlAuthenticationEntryPoint("/login/oauth/" + identityProviderConfigs.iterator().next().id);
        } else { // Go to the login page to get more context about the user logging in to be able to choose the correct identity provider flow
            delegate = new LoginUrlAuthenticationEntryPoint("/views/login");
        }

        delegate.commence(request, response, authException);
    }
}
