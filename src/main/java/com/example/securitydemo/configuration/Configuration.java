package com.example.securitydemo.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;

public class Configuration {

  @Bean
  public ObjectMapper objectMapper() {
    return new ObjectMapper();
  }
}
