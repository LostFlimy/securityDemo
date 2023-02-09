package com.example.securitydemo.configuration;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationEntryPoint;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.authentication.KeycloakLogoutHandler;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticatedActionsFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakCsrfRequestMatcher;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakSecurityContextRequestFilter;
import org.keycloak.adapters.springsecurity.management.HttpSessionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.stereotype.Component;

@Component
public class KeycloakConfigurer extends WebSecurityConfigurerAdapter {
  @Autowired
  ObjectBasedKeycloakConfigResolver keycloakConfigResolver;


  public AdapterDeploymentContext adapterDeploymentContext() throws Exception {
    return new AdapterDeploymentContext(keycloakConfigResolver.getKeycloakDeployment());
  }

  protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
    return new RegisterSessionAuthenticationStrategy(buildSessionRegistry());
  }

  protected SessionRegistry buildSessionRegistry() {
    return new SessionRegistryImpl();
  }

  public AuthenticationEntryPoint authenticationEntryPoint() throws Exception {
    return new KeycloakAuthenticationEntryPoint(adapterDeploymentContext());
  }

  public KeycloakAuthenticationProvider keycloakAuthenticationProvider() {
    return new KeycloakAuthenticationProvider();
  }

  public KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter() throws Exception {
    KeycloakAuthenticationProcessingFilter filter = new KeycloakAuthenticationProcessingFilter(authenticationManagerBean());
    filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy());
    return filter;
  }

  public KeycloakPreAuthActionsFilter keycloakPreAuthActionsFilter() {
    return new KeycloakPreAuthActionsFilter(httpSessionManager());
  }

  private KeycloakCsrfRequestMatcher keycloakCsrfRequestMatcher() {
    return new KeycloakCsrfRequestMatcher();
  }

  private HttpSessionManager httpSessionManager() {
    return new HttpSessionManager();
  }

  protected KeycloakLogoutHandler keycloakLogoutHandler() throws Exception {
    return new KeycloakLogoutHandler(adapterDeploymentContext());
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    if (keycloakConfigResolver.getKeycloakDeployment() == null) {
      throw new RuntimeException("Нету конфигурации keycloak в памяти");
    }
    http
        .csrf().requireCsrfProtectionMatcher(keycloakCsrfRequestMatcher())
        .and()
        .sessionManagement()
        .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
        .and()
        .addFilterBefore(keycloakPreAuthActionsFilter(), LogoutFilter.class)
        .addFilterBefore(keycloakAuthenticationProcessingFilter(), LogoutFilter.class)
        .addFilterAfter(keycloakSecurityContextRequestFilter(), SecurityContextHolderAwareRequestFilter.class)
        .addFilterAfter(keycloakAuthenticatedActionsRequestFilter(), KeycloakSecurityContextRequestFilter.class)
        .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
        .and()
        .logout()
        .addLogoutHandler(keycloakLogoutHandler())
        .logoutUrl("/sso/logout").permitAll()
        .logoutSuccessUrl("/");
  }

  private KeycloakSecurityContextRequestFilter keycloakSecurityContextRequestFilter() {
    return new KeycloakSecurityContextRequestFilter();
  }

  private KeycloakAuthenticatedActionsFilter keycloakAuthenticatedActionsRequestFilter() {
    return new KeycloakAuthenticatedActionsFilter();
  }
}
