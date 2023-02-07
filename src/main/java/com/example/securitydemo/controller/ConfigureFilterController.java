package com.example.securitydemo.controller;

import com.example.securitydemo.filter.LoggingFilter;
import com.example.securitydemo.filter.LoggingFilterSwitch;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.GenericWebApplicationContext;

@RestController
public class ConfigureFilterController {
  @Autowired
  private LoggingFilterSwitch filterSwitch;
  @Autowired
  private GenericWebApplicationContext context;

  @GetMapping("/configure/loggingFilter")
  public void configure() {
    filterSwitch.switchLogging();
//    if (!context.containsBean("loggingFilter")) {
//      enableFilter();
//      return;
//    }
//    context.removeBeanDefinition("loggingFilter");
  }

 private void registerFilter() {
   Objects.requireNonNull(context.getServletContext()).addFilter("loggingFilter", new LoggingFilter());
 }
}
