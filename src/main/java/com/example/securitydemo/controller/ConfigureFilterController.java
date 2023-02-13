package com.example.securitydemo.controller;

import com.example.securitydemo.configuration.ObjectBasedKeycloakConfigResolver;
import com.example.securitydemo.model.identityProvider.KeycloakConfig;
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

  @PostMapping ("/configure")
  public void configure(@RequestBody KeycloakConfig config) {


    // Старая реализация метода
//    filterSwitch.switchLogging();
//    if (!context.containsBean("loggingFilter")) {
//      enableFilter();
//      return;
//    }
//    context.removeBeanDefinition("loggingFilter");
  }

// private void registerFilter() {
//   Objects.requireNonNull(context.getServletContext()).addFilter("loggingFilter", new LoggingFilter());
// }
}
