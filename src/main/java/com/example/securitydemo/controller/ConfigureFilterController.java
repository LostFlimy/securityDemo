package com.example.securitydemo.controller;

import com.example.securitydemo.configuration.ObjectBasedKeycloakConfigResolver;
import com.example.securitydemo.filter.KeycloakIntegrationFilterState;
import com.example.securitydemo.filter.KeycloakOIDCFilterConfig;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.GenericWebApplicationContext;

@RestController
public class ConfigureFilterController {
  @Autowired
  private GenericWebApplicationContext context;
  @Autowired
  private ObjectBasedKeycloakConfigResolver keycloakConfigResolver;
  @Autowired
  private KeycloakOIDCFilterConfig filterConfig;
  @Autowired
  private KeycloakIntegrationFilterState state;

  @PostMapping("/configure")
  public void configure(@RequestBody Map<String, String> config) {
    state.setUpdated(true);
    filterConfig.storeConfig(config);
  }

   private void registerFilter() {
   }
}
