package com.example.securitydemo.filter;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class KeycloakIntegrationOIDCFilter extends KeycloakOIDCFilter {

  private FilterConfig filterConfiguration;

  @Autowired
  private KeycloakIntegrationFilterState state;

  @Autowired
  private KeycloakOIDCFilterConfig config;

  private String authServer;
  private String realm;
  private String resource;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    super.init(filterConfig);

    String pathParam = filterConfig.getInitParameter(CONFIG_PATH_PARAM);
    String path = pathParam == null ? "/keycloak.json" : pathParam;
    System.out.println("searching for config at path " + path);

    filterConfiguration = filterConfig;
    InputStream is = filterConfig.getServletContext().getResourceAsStream(path);
    InputStream is2 = filterConfig.getServletContext().getResourceAsStream(path);

    if (is != null) {
      AdapterConfig config = KeycloakDeploymentBuilder.loadAdapterConfig(is);
      KeycloakDeployment deployment = KeycloakDeploymentBuilder.build(is2);
      realm = config.getRealm();
      authServer = config.getAuthServerUrl();
      deploymentContext = new AdapterDeploymentContext(deployment);
      state.setConfigured(true);
      state.setUpdated(true);
    } else {
      System.out.println("Could not find configuration file");
      state.setConfigured(false);
    }

  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;

    if (state.isUpdated()) {
      handleUpdate(config);
    }
    if (!state.isConfigured()) {
      chain.doFilter(req, res);
      return;
    }
    HttpSession session = request.getSession();

    RefreshableKeycloakSecurityContext account = (RefreshableKeycloakSecurityContext) session.getAttribute(
        KeycloakSecurityContext.class.getName());

    if (request.getServletPath().contains("Logout")) {
      if (handleLogout(account, session)) {
        System.out.println("logout successful");

      } else {
        System.out.println("logout failed");
      }
      chain.doFilter(req, res);
      return;
    }

    super.doFilter(req, res, chain);
    chain.doFilter(req, res);
    return;
  }

  /**
   * @param account the Keycloak account to log out
   * @param session the session from which the user needs to be logged out
   * @return TRUE if the logout was successfully propagated to the AuthServer, FALSE otherwise
   */
  private boolean handleLogout(KeycloakSecurityContext account, HttpSession session) {
    if (session.getAttribute(KeycloakSecurityContext.class.getName()) != null) {
      System.out.println("removed security context");
      session.removeAttribute(KeycloakSecurityContext.class.getName());
    }
    if (session.getAttribute(KeycloakAccount.class.getName()) != null) {
      session.removeAttribute(KeycloakAccount.class.getName());
      System.out.println("removed account");
    }
    if (account != null) {
      System.out.println("attempting to logout user " + account.getIdToken().getPreferredUsername());
      HttpGet httpGet = new HttpGet();
      httpGet.setURI(URI.create(authServer + "/realms/" + realm + "/protocol" +
          "/openid-connect/logout?id_token_hint=" + account.getIdTokenString()));
      System.out.println("trying get with " + httpGet.getURI());

      try (CloseableHttpClient client = HttpClientBuilder.create().build()) {

        HttpResponse httpResponse = client.execute(httpGet);
        System.out.println(httpResponse.getStatusLine().toString());
        return true;
      } catch (Exception ex) {
        System.out.println("Caught exception " + ex);
      }
    }
    return false;
  }

  private void handleUpdate(KeycloakOIDCFilterConfig config) {
    state.setUpdated(false);

    try (InputStream is = filterConfiguration.getServletContext().getResourceAsStream("/keycloak.json")) {
      realm = config.get(KeycloakOIDCFilterConfig.REALM) != null ? (String) config.get(KeycloakOIDCFilterConfig.REALM) : realm;
      authServer = config.get(KeycloakOIDCFilterConfig.AUTH_SERVER_URL) != null ? (String) config.get(KeycloakOIDCFilterConfig.AUTH_SERVER_URL) : authServer;
      resource = config.get(KeycloakOIDCFilterConfig.RESOURCE) != null ? (String) config.get(KeycloakOIDCFilterConfig.RESOURCE) : resource;

      AdapterConfig adapterConfig = KeycloakDeploymentBuilder.loadAdapterConfig(is);

      String secret = (String) config.get(KeycloakOIDCFilterConfig.SECRET);
      Map<String, Object> credentials = adapterConfig.getCredentials();
      credentials.put("secret", secret);

      String realmPublicKey = (String) config.get(KeycloakOIDCFilterConfig.REALM_PUBLIC_KEY);

      String ssl = (String) config.get(KeycloakOIDCFilterConfig.SSL_REQUIRED);

      int confidentialPort;
      try {
        confidentialPort = Integer.parseInt((String) config.get(KeycloakOIDCFilterConfig.CONFIDENTIAL_PORT));
      } catch (NumberFormatException e) {
        confidentialPort = 8443;
      }

      //defaults to false
      boolean enableCors = Boolean.valueOf((String) config.get(KeycloakOIDCFilterConfig.ENABLE_CORS));

      int poolSize;
      try {
        poolSize = Integer.parseInt((String) config.get(KeycloakOIDCFilterConfig.CONNECTION_POOL_SIZE));
      } catch (NumberFormatException e) {
        //default value from Keycloak documentation
        poolSize = 20;
      }

      String proxy = config.get(KeycloakOIDCFilterConfig.PROXY_URL) != null ?
          (String) config.get(KeycloakOIDCFilterConfig.PROXY_URL) : adapterConfig.getProxyUrl();

      String truststore = config.get(KeycloakOIDCFilterConfig.TRUSTSTORE) != null ?
          (String) config.get(KeycloakOIDCFilterConfig.TRUSTSTORE) : adapterConfig.getTruststore();

      String truststorePassword = config.get(KeycloakOIDCFilterConfig.TRUSTSTORE_PASSWORD) != null ?
          (String) config.get(KeycloakOIDCFilterConfig.TRUSTSTORE_PASSWORD) : adapterConfig.getTruststorePassword();

      String clientKeystore = (String) config.get(KeycloakOIDCFilterConfig.CLIENT_KEYSTORE);

      int registerNodePeriod;
      try {
        registerNodePeriod = Integer.parseInt((String) config.get(KeycloakOIDCFilterConfig.REGISTER_NODE_PERIOD));
      } catch (NumberFormatException e) {
        registerNodePeriod = 60;
      }

      String tokenStore = config.get(KeycloakOIDCFilterConfig.TOKEN_STORE) != null ?
          (String) config.get(KeycloakOIDCFilterConfig.TOKEN_STORE) : "Session";

      String principalAttribute = config.get(KeycloakOIDCFilterConfig.PRINCIPAL_ATTRIBUTE) != null ?
          (String) config.get(KeycloakOIDCFilterConfig.PRINCIPAL_ATTRIBUTE) : "sub";

      int minTimeToLive;
      try {
        minTimeToLive = Integer.parseInt((String) config.get(KeycloakOIDCFilterConfig.TOKEN_MINIMUM_TIME_TO_LIVE));
      } catch (NumberFormatException e) {
        minTimeToLive = 0;
      }

      int timeBetweenJWKS;
      try {
        timeBetweenJWKS = Integer.parseInt((String) config.get(KeycloakOIDCFilterConfig.MIN_TIME_BETWEEN_JWKS_REQUEST));
      } catch (NumberFormatException e) {
        timeBetweenJWKS = 10;
      }

      int keyCacheTTL;
      try {
        keyCacheTTL = Integer.parseInt((String) config.get(KeycloakOIDCFilterConfig.PUBLIC_KEY_CACHE_TTL));
      } catch (NumberFormatException e) {
        keyCacheTTL = 86400;
      }

      adapterConfig.setRealm(realm);
      adapterConfig.setResource(resource);
      if (!StringUtils.isEmpty(realmPublicKey))
        adapterConfig.setRealmKey(realmPublicKey);
      else
        adapterConfig.setRealmKey(null);
      adapterConfig.setAuthServerUrl(authServer);
      adapterConfig.setSslRequired(ssl);
      adapterConfig.setUseResourceRoleMappings(Boolean.valueOf((String) config.get(KeycloakOIDCFilterConfig.USE_RESOURCE_ROLE_MAPPINGS)));
      adapterConfig.setConfidentialPort(confidentialPort);
      adapterConfig.setPublicClient(Boolean.valueOf((String) config.get(KeycloakOIDCFilterConfig.PUBLIC_CLIENT)));

      adapterConfig.setCors(enableCors);
      if (enableCors) {
        int corsMaxAge;
        try {
          corsMaxAge = Integer.parseInt((String) config.get(KeycloakOIDCFilterConfig.CORS_MAX_AGE));
        } catch (NumberFormatException e) {
          corsMaxAge = 20;
        }
        String allowedMethods = config.get(KeycloakOIDCFilterConfig.CORS_ALLOWED_METHODS) != null ?
            (String) config.get(KeycloakOIDCFilterConfig.CORS_ALLOWED_METHODS) : adapterConfig.getCorsAllowedMethods();
        String allowedHeaders = config.get(KeycloakOIDCFilterConfig.CORS_ALLOWED_HEADERS) != null ?
            (String) config.get(KeycloakOIDCFilterConfig.CORS_ALLOWED_HEADERS) : adapterConfig.getCorsAllowedHeaders();
        String exposedHeaders = config.get((KeycloakOIDCFilterConfig.CORS_EXPOSED_HEADERS)) != null ?
            (String) config.get(KeycloakOIDCFilterConfig.CORS_EXPOSED_HEADERS) : adapterConfig.getCorsExposedHeaders();

        adapterConfig.setCorsMaxAge(corsMaxAge);
        adapterConfig.setCorsAllowedMethods(allowedMethods);
        adapterConfig.setCorsAllowedHeaders(allowedHeaders);
        adapterConfig.setCorsExposedHeaders(exposedHeaders);
      }

      adapterConfig.setBearerOnly(Boolean.valueOf((String) config.get(KeycloakOIDCFilterConfig.BEARER_ONLY)));
      adapterConfig.setAutodetectBearerOnly(Boolean.valueOf((String) config.get(KeycloakOIDCFilterConfig.AUTODETECT_BEARER_ONLY)));
      adapterConfig.setEnableBasicAuth(Boolean.valueOf((String) config.get(KeycloakOIDCFilterConfig.ENABLE_BASIC_AUTH)));
      adapterConfig.setExposeToken(Boolean.valueOf((String) config.get(KeycloakOIDCFilterConfig.EXPOSE_TOKEN)));
      adapterConfig.setCredentials(credentials);
      adapterConfig.setConnectionPoolSize(poolSize);
      adapterConfig.setDisableTrustManager(Boolean.valueOf(KeycloakOIDCFilterConfig.DISABLE_TRUST_MANAGER));
      adapterConfig.setAllowAnyHostname(Boolean.valueOf(KeycloakOIDCFilterConfig.ALLOW_ANY_HOSTNAME));
      if (!StringUtils.isEmpty(proxy))
        adapterConfig.setProxyUrl(proxy);
      else
        adapterConfig.setProxyUrl(null);
      if (!StringUtils.isEmpty(truststore))
        adapterConfig.setTruststore(truststore);
      else
        adapterConfig.setTruststore(null);
      if (!StringUtils.isEmpty(truststorePassword))
        adapterConfig.setTruststorePassword(truststorePassword);
      else
        adapterConfig.setTruststore(null);
      if (!StringUtils.isEmpty(clientKeystore)) {
        adapterConfig.setClientKeystore(clientKeystore);
        if (!StringUtils.isEmpty((String) config.get(KeycloakOIDCFilterConfig.CLIENT_KEYSTORE_PASSWORD)))
          adapterConfig.setClientKeystorePassword((String) config.get(KeycloakOIDCFilterConfig.CLIENT_KEYSTORE_PASSWORD));
        if (!StringUtils.isEmpty((String) config.get(KeycloakOIDCFilterConfig.CLIENT_KEY_PASSWORD)))
          adapterConfig.setClientKeyPassword((String) config.get(KeycloakOIDCFilterConfig.CLIENT_KEY_PASSWORD));
      } else
        adapterConfig.setClientKeystore(null);

      adapterConfig.setAlwaysRefreshToken(Boolean.valueOf((String) config.get(KeycloakOIDCFilterConfig.ALWAYS_REFRESH_TOKEN)));
      adapterConfig.setRegisterNodeAtStartup(Boolean.valueOf((String) config.get(KeycloakOIDCFilterConfig.REGISTER_NODE_AT_STARTUP)));
      adapterConfig.setRegisterNodePeriod(registerNodePeriod);
      adapterConfig.setTokenStore(tokenStore);
      if (tokenStore.equalsIgnoreCase("Cookie")) {
        adapterConfig.setTokenCookiePath((String) config.get(KeycloakOIDCFilterConfig.TOKEN_COOKIE_PATH));
      }
      adapterConfig.setPrincipalAttribute(principalAttribute);
      adapterConfig.setTurnOffChangeSessionIdOnLogin(Boolean.valueOf((String) config.get(KeycloakOIDCFilterConfig.TURN_OFF_CHANGE_SESSION_ID_ON_LOGIN)));
      adapterConfig.setTokenMinimumTimeToLive(minTimeToLive);
      adapterConfig.setMinTimeBetweenJwksRequests(timeBetweenJWKS);
      adapterConfig.setPublicKeyCacheTtl(keyCacheTTL);
      adapterConfig.setVerifyTokenAudience(Boolean.valueOf((String) config.get(KeycloakOIDCFilterConfig.VERIFY_AUDIENCE)));

      KeycloakDeployment ment = KeycloakDeploymentBuilder.build(adapterConfig);
      deploymentContext = new AdapterDeploymentContext(ment);
      System.out.println("updated settings");
    } catch (Exception e) {
      System.out.println("failed during updated due to " + e.getMessage());
    }
  }

  private void initFromConfig(AdapterConfig config, KeycloakOIDCFilterConfig toStore) {

    System.out.println("Started initial configuration");
    toStore.put(KeycloakOIDCFilterConfig.REALM, config.getRealm());
    toStore.put(KeycloakOIDCFilterConfig.RESOURCE, config.getResource());
    toStore.put(KeycloakOIDCFilterConfig.REALM_PUBLIC_KEY, config.getRealmKey());
    toStore.put(KeycloakOIDCFilterConfig.AUTH_SERVER_URL, config.getAuthServerUrl());
    toStore.put(KeycloakOIDCFilterConfig.SSL_REQUIRED, config.getSslRequired());
    toStore.put(KeycloakOIDCFilterConfig.CONFIDENTIAL_PORT, getString(config.getConfidentialPort()));
    toStore.put(KeycloakOIDCFilterConfig.USE_RESOURCE_ROLE_MAPPINGS, getString(config.isUseResourceRoleMappings()));
    toStore.put(KeycloakOIDCFilterConfig.PUBLIC_CLIENT, getString(config.isPublicClient()));
    System.out.println("setting CORS options");
    toStore.put(KeycloakOIDCFilterConfig.ENABLE_CORS, getString(config.isCors()));
    toStore.put(KeycloakOIDCFilterConfig.CORS_ALLOWED_HEADERS, config.getCorsAllowedHeaders());
    toStore.put(KeycloakOIDCFilterConfig.CORS_ALLOWED_METHODS, config.getCorsAllowedMethods());
    toStore.put(KeycloakOIDCFilterConfig.CORS_EXPOSED_HEADERS, config.getCorsExposedHeaders());
    toStore.put(KeycloakOIDCFilterConfig.CORS_MAX_AGE, getString(config.getCorsMaxAge()));
    toStore.put(KeycloakOIDCFilterConfig.BEARER_ONLY, getString(config.isBearerOnly()));
    toStore.put(KeycloakOIDCFilterConfig.AUTODETECT_BEARER_ONLY, getString(config.isAutodetectBearerOnly()));
    toStore.put(KeycloakOIDCFilterConfig.ENABLE_BASIC_AUTH, getString(config.isEnableBasicAuth()));
    toStore.put(KeycloakOIDCFilterConfig.EXPOSE_TOKEN, getString(config.isExposeToken()));
    toStore.put(KeycloakOIDCFilterConfig.SECRET, (String) config.getCredentials().get("secret"));
    toStore.put(KeycloakOIDCFilterConfig.CONNECTION_POOL_SIZE, getString(config.getConnectionPoolSize()));
    toStore.put(KeycloakOIDCFilterConfig.DISABLE_TRUST_MANAGER, getString(config.isDisableTrustManager()));
    toStore.put(KeycloakOIDCFilterConfig.ALLOW_ANY_HOSTNAME, getString(config.isAllowAnyHostname()));
    toStore.put(KeycloakOIDCFilterConfig.PROXY_URL, config.getProxyUrl());
    System.out.println("setting truststore stuff");
    toStore.put(KeycloakOIDCFilterConfig.TRUSTSTORE, config.getTruststore());
    toStore.put(KeycloakOIDCFilterConfig.TRUSTSTORE_PASSWORD, config.getTruststorePassword());
    toStore.put(KeycloakOIDCFilterConfig.CLIENT_KEYSTORE, config.getClientKeystore());
    toStore.put(KeycloakOIDCFilterConfig.CLIENT_KEYSTORE_PASSWORD, config.getClientKeystorePassword());
    toStore.put(KeycloakOIDCFilterConfig.CLIENT_KEY_PASSWORD, config.getClientKeyPassword());
    toStore.put(KeycloakOIDCFilterConfig.ALWAYS_REFRESH_TOKEN, getString(config.isAlwaysRefreshToken()));
    toStore.put(KeycloakOIDCFilterConfig.REGISTER_NODE_PERIOD, getString(config.getRegisterNodePeriod()));
    toStore.put(KeycloakOIDCFilterConfig.REGISTER_NODE_AT_STARTUP, getString(config.isRegisterNodeAtStartup()));
    toStore.put(KeycloakOIDCFilterConfig.TOKEN_STORE, config.getTokenStore());
    toStore.put(KeycloakOIDCFilterConfig.TOKEN_COOKIE_PATH, config.getTokenCookiePath());
    toStore.put(KeycloakOIDCFilterConfig.PRINCIPAL_ATTRIBUTE, config.getPrincipalAttribute());
    toStore.put(KeycloakOIDCFilterConfig.TURN_OFF_CHANGE_SESSION_ID_ON_LOGIN, getString(config.getTurnOffChangeSessionIdOnLogin()));
    toStore.put(KeycloakOIDCFilterConfig.TOKEN_MINIMUM_TIME_TO_LIVE, getString(config.getTokenMinimumTimeToLive()));
    toStore.put(KeycloakOIDCFilterConfig.MIN_TIME_BETWEEN_JWKS_REQUEST, getString(config.getMinTimeBetweenJwksRequests()));
    toStore.put(KeycloakOIDCFilterConfig.PUBLIC_KEY_CACHE_TTL, getString(config.getPublicKeyCacheTtl()));
    toStore.put(KeycloakOIDCFilterConfig.IGNORE_OAUTH_QUERY_PARAM, getString(config.isIgnoreOAuthQueryParameter()));
    toStore.put(KeycloakOIDCFilterConfig.VERIFY_AUDIENCE, getString(config.isVerifyTokenAudience()));
  }

  private String getString(Integer number) {

    if (number == null) {
      number = -1;
    }
    return number.toString();
  }

  private String getString(Boolean bool) {

    if (bool == null)
      bool = Boolean.FALSE;
    return bool.toString();
  }
}
