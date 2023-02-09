package com.example.securitydemo.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.spi.HttpFacade.Request;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.stereotype.Component;

@Component
public class ObjectBasedKeycloakConfigResolver implements KeycloakConfigResolver {

  @Autowired
  private GenericApplicationContext context;

  private KeycloakDeployment keycloakDeployment;

  final ObjectMapper mapper;

  @Autowired
  public ObjectBasedKeycloakConfigResolver(ObjectMapper mapper) {
    this.mapper = mapper;
  }

  public void setKeycloakDeployment(AdapterConfig keycloakConfig) {
    this.keycloakDeployment = KeycloakDeploymentBuilder.build(keycloakConfig);
    if (context.containsBean("adapterDeploymentContext")) {
      return;
    }
    context.registerBean("adapterDeploymentContext", AdapterDeploymentContext.class, new AdapterDeploymentContext(this.keycloakDeployment));
  }

  public KeycloakDeployment getKeycloakDeployment() {
    return keycloakDeployment;
  }

  /**
   * Resolves the KeycloakDeployment based on the Request
   *
   * @param facade The request
   * @return KeycloakDeployment, may never be null
   */
  @Override
  public KeycloakDeployment resolve(Request facade) {
    return keycloakDeployment;
  }
}
