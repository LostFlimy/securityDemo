package com.example.securitydemo.filter;

import com.example.securitydemo.model.identityProvider.IdPConfig;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import org.springframework.stereotype.Component;
import java.util.Map;

@Component
public class KeycloakOIDCFilterConfig implements IdPConfig {
  public static final String REALM = "realm";
  public static final String PUBLIC_CLIENT = "public-client";
  public static final String RESOURCE = "resource";
  public static final String AUTH_SERVER_URL = "auth-server-url";
  public static final String SECRET = "secret";
  public static final String REALM_PUBLIC_KEY = "realm-public-key";
  public static final String SSL_REQUIRED = "ssl-required";
  public static final String CONFIDENTIAL_PORT = "confidential-port";
  public static final String USE_RESOURCE_ROLE_MAPPINGS = "use-resource-role-mappings";
  public static final String ENABLE_CORS = "enable-cors";
  public static final String CORS_MAX_AGE = "cors-max-age";
  public static final String CORS_ALLOWED_METHODS = "cors-allowed-methods";
  public static final String CORS_ALLOWED_HEADERS = "cors-allowed-headers";
  public static final String CORS_EXPOSED_HEADERS = "cors-exposed-headers";
  public static final String BEARER_ONLY = "bearer-only";
  public static final String AUTODETECT_BEARER_ONLY = "autodetect-bearer-only";
  public static final String ENABLE_BASIC_AUTH = "enable-basic-auth";
  public static final String EXPOSE_TOKEN = "expose-token";
  public static final String CONNECTION_POOL_SIZE = "connection-pool-size";
  public static final String DISABLE_TRUST_MANAGER = "disable-trust-manager";
  public static final String ALLOW_ANY_HOSTNAME = "allow-any-hostname";
  public static final String PROXY_URL = "proxy-url";
  public static final String TRUSTSTORE = "truststore";
  public static final String TRUSTSTORE_PASSWORD = "truststore-password";
  public static final String CLIENT_KEYSTORE = "client-keystore";
  public static final String CLIENT_KEYSTORE_PASSWORD = "client-keystore-password";
  public static final String CLIENT_KEY_PASSWORD = "client-key-password";
  public static final String ALWAYS_REFRESH_TOKEN = "always-refresh-token";
  public static final String REGISTER_NODE_AT_STARTUP = "register-node-at-startup";
  public static final String REGISTER_NODE_PERIOD = "register-node-period";
  public static final String TOKEN_STORE = "token-store";
  public static final String TOKEN_COOKIE_PATH = "token-cookie-path";
  public static final String PRINCIPAL_ATTRIBUTE = "principal-attribute";
  public static final String TURN_OFF_CHANGE_SESSION_ID_ON_LOGIN = "turn-off-change-session-id-on-login";
  public static final String TOKEN_MINIMUM_TIME_TO_LIVE = "token-minimum-time-to-live";
  public static final String MIN_TIME_BETWEEN_JWKS_REQUEST = "min-time-between-jwks-requests";
  public static final String PUBLIC_KEY_CACHE_TTL = "public-key-cache-ttl";
  public static final String IGNORE_OAUTH_QUERY_PARAM = "ignore-oauth-query-parameter";
  public static final String VERIFY_AUDIENCE = "verify-token-audience";

  public static List<String> validValues = Arrays.asList(REALM, AUTH_SERVER_URL, RESOURCE, PUBLIC_CLIENT, SECRET,
      REALM_PUBLIC_KEY, REGISTER_NODE_AT_STARTUP, REGISTER_NODE_PERIOD, SSL_REQUIRED, CONFIDENTIAL_PORT,
      USE_RESOURCE_ROLE_MAPPINGS, ENABLE_CORS, CORS_MAX_AGE, CORS_ALLOWED_HEADERS, CORS_ALLOWED_METHODS,
      CORS_EXPOSED_HEADERS, BEARER_ONLY, AUTODETECT_BEARER_ONLY, ENABLE_BASIC_AUTH, EXPOSE_TOKEN,
      CONNECTION_POOL_SIZE, DISABLE_TRUST_MANAGER, ALLOW_ANY_HOSTNAME, PROXY_URL, TRUSTSTORE, TRUSTSTORE_PASSWORD,
      CLIENT_KEYSTORE, CLIENT_KEYSTORE_PASSWORD, CLIENT_KEY_PASSWORD, ALWAYS_REFRESH_TOKEN, TOKEN_STORE, TOKEN_COOKIE_PATH,
      PRINCIPAL_ATTRIBUTE, TURN_OFF_CHANGE_SESSION_ID_ON_LOGIN, TOKEN_MINIMUM_TIME_TO_LIVE, MIN_TIME_BETWEEN_JWKS_REQUEST,
      PUBLIC_KEY_CACHE_TTL, IGNORE_OAUTH_QUERY_PARAM, VERIFY_AUDIENCE);

  private final Map<String, String> keycloakConfig;

  public KeycloakOIDCFilterConfig() {
    this.keycloakConfig = new HashMap<>();
  }

  public String get(String key) {
    return keycloakConfig.get(key);
  }

  public void put(String key, String value) {
    keycloakConfig.put(key, value);
  }

  public void storeConfig(Map<String, String> config) {
    for (String key : config.keySet()) {
      if (isValidKey(key)) {
        keycloakConfig.put(key, config.get(key));
      }
    }
  }

  private boolean isValidKey(String key) {
    return validValues.contains(key);
  }
}
