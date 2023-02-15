package com.example.securitydemo.filter;

import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
public class KeycloakIntegrationFilterState {
  private boolean configured = false;
  private boolean updated = false;
}
