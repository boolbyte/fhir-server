package ca.uhn.fhir.jpa.starter.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SmartTenantResolver {

  @Value("${hapi.fhir.security.smart.default-organization:default}")
  private String defaultOrganization;

  @Value("${hapi.fhir.security.smart.base-domain:fhir.boolbyte.com}")
  private String baseDomain;

  private final SmartProperties smartProperties;

  public SmartTenantResolver(SmartProperties smartProperties) {
    this.smartProperties = smartProperties;
  }

  public String resolveTenantFromUrl(HttpServletRequest request) {
    String host = request.getHeader("Host");

    if (host == null || host.isBlank()) {
      return defaultOrganization;
    }

    if (host.contains(":")) {
      host = host.substring(0, host.indexOf(":"));
    }

    if (host.endsWith("." + baseDomain)) {
      String subdomain = host.substring(0, host.length() - baseDomain.length() - 1);
      if (subdomain != null && !subdomain.isEmpty() && !subdomain.equals("www")) {
        return subdomain;
      }
    }

    return defaultOrganization;
  }

  public String getRealmFromIssuer(String issuer) {
    if (issuer == null || issuer.isBlank()) {
      return null;
    }

    String pattern = "/realms/";
    int index = issuer.lastIndexOf(pattern);
    if (index >= 0) {
      return issuer.substring(index + pattern.length());
    }
    return null;
  }

  public String getKeycloakUrl(String organizationId) {
    return smartProperties.getKeycloakUrl(organizationId);
  }

  public String getDefaultOrganization() {
    return defaultOrganization;
  }

  public String getBaseDomain() {
    return baseDomain;
  }
}
