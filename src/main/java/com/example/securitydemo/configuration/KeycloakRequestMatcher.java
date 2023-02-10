package com.example.securitydemo.configuration;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class KeycloakRequestMatcher implements RequestMatcher {
    private final ObjectBasedKeycloakConfigResolver keycloakConfigResolver;

    public KeycloakRequestMatcher(ObjectBasedKeycloakConfigResolver keycloakConfigResolver) {
        this.keycloakConfigResolver = keycloakConfigResolver;
    }

    @Override
    public boolean matches(HttpServletRequest httpServletRequest) {
        if (keycloakConfigResolver.getKeycloakDeployment() == null
                || !keycloakConfigResolver.getKeycloakDeployment().isConfigured()) {
            return false;
        }
        String url = "/configure";
        AntPathRequestMatcher antPathRequestMatcher = new AntPathRequestMatcher(url);
        return antPathRequestMatcher.matches(httpServletRequest);
    }
}
