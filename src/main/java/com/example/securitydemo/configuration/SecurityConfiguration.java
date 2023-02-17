package com.example.securitydemo.configuration;

import java.util.Arrays;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;


@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails admin = User.withDefaultPasswordEncoder()
        .username("admin")
        .password("password")
        .roles("USER", "ADMIN")
        .build();

    UserDetails user = User.withDefaultPasswordEncoder()
        .username("user")
        .password("password")
        .roles("USER")
        .build();
    return new InMemoryUserDetailsManager(user, admin);
  }

  @Bean public AuthenticationManager authenticationManager() {
    return new ProviderManager(Arrays.asList(keycloakAuthenticationProvider(), daoAuthenticationProvider()));
  }

  @Bean public KeycloakAuthenticationProvider keycloakAuthenticationProvider() {
    return new KeycloakAuthenticationProvider();
  }

  @Bean public DaoAuthenticationProvider daoAuthenticationProvider() {
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(userDetailsService());
    return provider;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable().userDetailsService(userDetailsService())
        .cors().and()
        .authorizeRequests()
        .antMatchers("/hello").hasRole("USER")
        .antMatchers("/hi").permitAll()
        .antMatchers("/configure").hasRole("ADMIN")
        .and()
        .formLogin().defaultSuccessUrl("/hello");
  }
}
