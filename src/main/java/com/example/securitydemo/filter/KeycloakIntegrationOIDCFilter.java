package com.example.securitydemo.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;

public class KeycloakIntegrationOIDCFilter extends KeycloakOIDCFilter {

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    super.init(filterConfig);


  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
    super.doFilter(req, res, chain);
  }
}
