package ca.uhn.fhir.jpa.starter.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class SmartConfigurationController {

  private final SmartProperties smartProperties;
  private final SmartTenantResolver tenantResolver;

  @Autowired
  public SmartConfigurationController(SmartProperties smartProperties, SmartTenantResolver tenantResolver) {
    this.smartProperties = smartProperties;
    this.tenantResolver = tenantResolver;
  }

  @GetMapping(
    value = {
      "/.well-known/smart-configuration",
      "/fhir/.well-known/smart-configuration"
    },
    produces = MediaType.APPLICATION_JSON_VALUE
  )
  public ResponseEntity<Map<String, Object>> getSmartConfiguration(HttpServletRequest request) {
    String subdomain = tenantResolver.resolveTenantFromUrl(request);
    String baseUrl = getBaseUrl(request);

    String keycloakUrl = tenantResolver.getKeycloakUrl(subdomain);
    String realm = smartProperties.getRealm();

    Map<String, Object> config = new HashMap<>();

    config.put("authorization_endpoint", keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/auth");
    config.put("token_endpoint", keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token");

    List<String> capabilities = new ArrayList<>();
    capabilities.add("launch-ehr");
    capabilities.add("client-confidential-symmetric");
    capabilities.add("sso-openid-connect");
    capabilities.add("context-passthrough-bearer");
    config.put("capabilities", capabilities);

    List<String> scopesSupported = new ArrayList<>();
    scopesSupported.add("openid");
    scopesSupported.add("fhirUser");
    scopesSupported.add("launch/patient");
    scopesSupported.add("launch/encounter");
    scopesSupported.add("patient/*.read");
    scopesSupported.add("patient/*.write");
    scopesSupported.add("user/*.read");
    scopesSupported.add("user/*.write");
    scopesSupported.add("system/*.read");
    scopesSupported.add("system/*.write");
    scopesSupported.add("offline_access");
    scopesSupported.add("online_access");
    config.put("scopes_supported", scopesSupported);

    List<String> responseTypesSupported = new ArrayList<>();
    responseTypesSupported.add("code");
    config.put("response_types_supported", responseTypesSupported);

    List<String> codeChallengeMethodsSupported = new ArrayList<>();
    codeChallengeMethodsSupported.add("S256");
    config.put("code_challenge_methods_supported", codeChallengeMethodsSupported);

    config.put("issuer", keycloakUrl + "/realms/" + realm);

    config.put("jwks_uri", keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/certs");

    config.put("aud", baseUrl);

    return ResponseEntity.ok(config);
  }

  private String getBaseUrl(HttpServletRequest request) {
    String scheme = request.getScheme();
    String serverName = request.getServerName();
    int serverPort = request.getServerPort();
    String contextPath = request.getContextPath();

    String baseUrl = scheme + "://" + serverName;

    if ((scheme.equals("http") && serverPort != 80) ||
      (scheme.equals("https") && serverPort != 443)) {
      baseUrl += ":" + serverPort;
    }

    if (contextPath != null && !contextPath.isEmpty()) {
      baseUrl += contextPath;
    }

    if (baseUrl.endsWith("/fhir")) {
      baseUrl = baseUrl.substring(0, baseUrl.length() - 4);
    }

    return baseUrl;
  }
}
