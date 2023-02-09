package com.example.securitydemo.model.identityProvider;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class KeycloakConfig implements IdPConfig {
  @JsonProperty("enabled")
  private Boolean enabled;
  @JsonProperty("ssl-required")
  private String sslRequired;
  @JsonProperty("auth-server-url")
  private String authServerUrl;
  @JsonProperty("realm")
  private String realm;
  @JsonProperty("resource")
  private String resource;
  @JsonProperty("public-client")
  private Boolean publicClient;
  @JsonProperty("credentials")
  private CredentialsKeycloak credential;
  @JsonProperty("use-resource-role-mappings")
  private Boolean useResourceRoleMapping;
  @JsonProperty("bearer-only")
  private Boolean bearerOnly;
  @JsonProperty("principal-attribute")
  private String principalAttribute;

  @Data
  private class CredentialsKeycloak {
    @JsonProperty("secret")
    private String secret;
  }
}
