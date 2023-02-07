package com.example.securitydemo.filter;


import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@Order(1)
public class LoggingFilter implements Filter {
  @Autowired
  LoggingFilterSwitch filterSwitch;

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {
    if (filterSwitch.isEnabled()) {
      log.info(servletRequest.toString());
    }
    filterChain.doFilter(servletRequest, servletResponse);
  }
}

