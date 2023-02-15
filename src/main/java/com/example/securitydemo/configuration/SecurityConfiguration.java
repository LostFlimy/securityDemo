package com.example.securitydemo.configuration;

import java.util.Arrays;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;


@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

  @Override
  @Order(1)
  protected void configure (AuthenticationManagerBuilder http) throws Exception {
   http.authenticationProvider(keycloakAuthenticationProvider());
  }

  @Order(2)
  protected void configureGlobal(AuthenticationManagerBuilder http) throws Exception {
    http.userDetailsService(users()).and().authenticationProvider();
  }

  @Bean public AuthenticationManager authenticationManager() {
    return new ProviderManager(Arrays.asList(keycloakAuthenticationProvider()));
  }

  @Bean public KeycloakAuthenticationProvider keycloakAuthenticationProvider() {
    return new KeycloakAuthenticationProvider();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable()
        .cors().and()
        .authorizeRequests()
        .antMatchers("/hello").hasRole("USER")
        .antMatchers("/hi").permitAll()
        .antMatchers("/configure").hasRole("ADMIN")
        .and()
        .formLogin().successForwardUrl("/hello");
  }

  @Bean
  public UserDetailsService users() {
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

}
