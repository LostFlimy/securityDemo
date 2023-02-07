package com.example.securitydemo.filter;

import org.springframework.stereotype.Component;

@Component
public class LoggingFilterSwitch {
  private boolean enabled;

  public LoggingFilterSwitch() {
    enabled = false;
  }

  public void switchLogging() {
    enabled = !enabled;
  }

  public boolean isEnabled() {
    return enabled;
  }
}
