package com.example.securitydemo.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationEntryPoint;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.authentication.KeycloakLogoutHandler;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.*;
import org.keycloak.adapters.springsecurity.management.HttpSessionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;


import java.util.ArrayList;
import java.util.List;
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends KeycloakWebSecurityConfigurerAdapter {

  @Autowired
  private ObjectBasedKeycloakConfigResolver keycloakConfigResolver;

  public AdapterDeploymentContext adapterDeploymentContext() throws Exception {
    return new AdapterDeploymentContext(keycloakConfigResolver.getKeycloakDeployment());
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

  protected KeycloakCsrfRequestMatcher keycloakCsrfRequestMatcher() {
    return new KeycloakCsrfRequestMatcher();
  }

  protected HttpSessionManager httpSessionManager() {
    return new HttpSessionManager();
  }

  protected KeycloakLogoutHandler keycloakLogoutHandler() throws Exception {
    return new KeycloakLogoutHandler(adapterDeploymentContext());
  }

  @Override
  protected void configure (HttpSecurity http) throws Exception {
   http
        .csrf().requireCsrfProtectionMatcher(keycloakCsrfRequestMatcher())
        .and()
        .sessionManagement()
        .sessionAuthenticationStrategy(sessionAuthenticationStrategy()).and()
           .addFilterBefore(keycloakFilterChainBefore(), LogoutFilter.class)
           .addFilterAfter(keycloakFilterChainAfter1(), SecurityContextHolderAwareRequestFilter.class)
           .addFilterAfter(keycloakFilterChainAfter2(), KeycloakSecurityContextRequestFilter.class)
        .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint()).and()
        .logout()
        .addLogoutHandler(keycloakLogoutHandler())
        .logoutUrl("/sso/logout").permitAll()
        .logoutSuccessUrl("/");
  }

  private FilterChainProxy keycloakFilterChainBefore() throws Exception {
    List<SecurityFilterChain> chains = new ArrayList<>();
    chains.add(new DefaultSecurityFilterChain(new KeycloakRequestMatcher(keycloakConfigResolver), keycloakPreAuthActionsFilter()));
    chains.add(new DefaultSecurityFilterChain(new KeycloakRequestMatcher(keycloakConfigResolver), keycloakAuthenticationProcessingFilter()));
    return new FilterChainProxy(chains);
  }

  private FilterChainProxy keycloakFilterChainAfter1() throws Exception {
    List<SecurityFilterChain> chains = new ArrayList<>();
    chains.add(new DefaultSecurityFilterChain(new KeycloakRequestMatcher(keycloakConfigResolver), keycloakSecurityContextRequestFilter()));
    return new FilterChainProxy(chains);
  }

  private FilterChainProxy keycloakFilterChainAfter2() throws Exception {
    List<SecurityFilterChain> chains = new ArrayList<>();
    chains.add(new DefaultSecurityFilterChain(new KeycloakRequestMatcher(keycloakConfigResolver), keycloakAuthenticatedActionsRequestFilter()));
    return new FilterChainProxy(chains);
  }


  public KeycloakSecurityContextRequestFilter keycloakSecurityContextRequestFilter() {
    return new KeycloakSecurityContextRequestFilter();
  }

  public KeycloakAuthenticatedActionsFilter keycloakAuthenticatedActionsRequestFilter() {
    return new KeycloakAuthenticatedActionsFilter();
  }

  @Bean
  public KeycloakConfigResolver resolver(ObjectMapper mapper) {
    return new ObjectBasedKeycloakConfigResolver(mapper);
  }

  @Bean
  protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
    return new RegisterSessionAuthenticationStrategy(buildSessionRegistry());
  }

  @Bean
  protected SessionRegistry buildSessionRegistry() {
    return new SessionRegistryImpl();
  }

  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails user =
        User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("ADMIN")
            .build();

    return new InMemoryUserDetailsManager(user);
  }
}
