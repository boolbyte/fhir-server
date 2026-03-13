package ca.uhn.fhir.jpa.starter.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SmartTokenValidationService {

  private static final Logger ourLog = LoggerFactory.getLogger(SmartTokenValidationService.class);

  private final SmartProperties smartProperties;
  private final SmartTenantResolver tenantResolver;
  private final ObjectMapper objectMapper;
  private final HttpClient httpClient;
  private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();

  public SmartTokenValidationService(SmartProperties smartProperties, SmartTenantResolver tenantResolver) {
    this.smartProperties = smartProperties;
    this.tenantResolver = tenantResolver;
    this.objectMapper = new ObjectMapper();
    this.httpClient = HttpClient.newHttpClient();
  }

  public TokenValidationResult validateToken(String bearerToken) {
    try {
      if (bearerToken == null || bearerToken.isBlank()) {
        ourLog.warn("Token validation failed: Missing token");
        return TokenValidationResult.failure("Invalid token");
      }

      String token = bearerToken.startsWith("Bearer ") ? bearerToken.substring(7) : bearerToken;
      String[] parts = token.split("\\.");
      if (parts.length != 3) {
        ourLog.warn("Token validation failed: Invalid token format - expected 3 parts, got {}", parts.length);
        return TokenValidationResult.failure("Invalid token");
      }

      String headerJson = decodeBase64Url(parts[0]);
      String payloadJson = decodeBase64Url(parts[1]);

      JsonNode headerNode = objectMapper.readTree(headerJson);
      JsonNode payloadNode = objectMapper.readTree(payloadJson);

      String issuer = payloadNode.has("iss") ? payloadNode.get("iss").asText() : null;
      if (issuer == null || issuer.isBlank()) {
        ourLog.warn("Token validation failed: Missing issuer claim in token");
        return TokenValidationResult.failure("Invalid token");
      }

      String organizationId = payloadNode.has("organization_id")
        ? payloadNode.get("organization_id").asText()
        : null;

      String clientId = payloadNode.has("client_id")
        ? payloadNode.get("client_id").asText()
        : null;

      boolean isSystemClient =
        clientId != null &&
        smartProperties.getSystemClientId() != null &&
        clientId.equals(smartProperties.getSystemClientId());

      if ((organizationId == null || organizationId.isBlank()) && !isSystemClient) {
        ourLog.warn("Token validation failed: Missing organization_id claim in token for non-system client");
        return TokenValidationResult.failure("Invalid token");
      }

      if (isSystemClient) {
        organizationId = smartProperties.getDefaultOrganization();
      }

      String keycloakUrl = tenantResolver.getKeycloakUrl(organizationId);
      String realm = smartProperties.getRealm();

      String kid = headerNode.has("kid") ? headerNode.get("kid").asText() : null;
      String alg = headerNode.has("alg") ? headerNode.get("alg").asText() : null;

      if (!"RS256".equals(alg) && !"RS384".equals(alg) && !"RS512".equals(alg)) {
        ourLog.warn("Token validation failed for organization {}: Unsupported algorithm: {}", organizationId, alg);
        return TokenValidationResult.failure("Invalid token");
      }

      PublicKey publicKey = getPublicKey(kid, headerNode, organizationId, keycloakUrl, realm);

      if (publicKey == null) {
        ourLog.warn("Token validation failed for organization {}: Unable to obtain public key", organizationId);
        return TokenValidationResult.failure("Invalid token");
      }

      if (!validateSignature(parts, publicKey, alg)) {
        ourLog.warn("Token validation failed for organization {}: Invalid signature", organizationId);
        return TokenValidationResult.failure("Invalid token");
      }

      if (!validateExpiration(payloadNode)) {
        ourLog.warn("Token validation failed for organization {}: Token expired", organizationId);
        return TokenValidationResult.failure("Invalid token");
      }

      if (!validateIssuer(payloadNode, keycloakUrl, realm)) {
        ourLog.warn("Token validation failed for organization {}: Invalid issuer. Got: {}", 
          organizationId, issuer);
        return TokenValidationResult.failure("Invalid token");
      }

      List<String> scopes = parseScopes(payloadNode);
      String patientId = payloadNode.has("patient") ? payloadNode.get("patient").asText() : null;
      String fhirUser = payloadNode.has("fhirUser") ? payloadNode.get("fhirUser").asText() : null;
      String subject = payloadNode.has("sub") ? payloadNode.get("sub").asText() : null;
      String encounterId = payloadNode.has("encounter") ? payloadNode.get("encounter").asText() : null;

      ourLog.debug("Token validated successfully for organization: {}, subject: {}, scopes: {}", 
        organizationId, subject, scopes);

      return TokenValidationResult.success(
        subject,
        scopes,
        patientId,
        fhirUser,
        encounterId,
        payloadNode,
        organizationId
      );

    } catch (Exception e) {
      ourLog.error("Token validation failed with unexpected error: {}", e.getMessage(), e);
      return TokenValidationResult.failure("Invalid token");
    }
  }

  private PublicKey getPublicKey(String kid, JsonNode headerNode, String organizationId, String keycloakUrl, String realm) {
    String cacheKey = organizationId + ":" + (kid != null ? kid : "default");

    if (kid != null && keyCache.containsKey(cacheKey)) {
      return keyCache.get(cacheKey);
    }

    refreshJwks(organizationId, keycloakUrl, realm);

    if (kid != null && keyCache.containsKey(cacheKey)) {
      return keyCache.get(cacheKey);
    }

    if (!headerNode.has("kid")) {
      return keyCache.values().stream().findFirst().orElse(null);
    }

    return null;
  }

  private void refreshJwks(String organizationId, String keycloakUrl, String realm) {
    try {
      String jwksUri = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/certs";
      ourLog.info("Refreshing JWKS for organization {} from URL {}", organizationId, jwksUri);
      HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(jwksUri))
        .GET()
        .timeout(java.time.Duration.ofSeconds(10))
        .build();

      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() == 200) {
        JsonNode jwks = objectMapper.readTree(response.body());
        JsonNode keys = jwks.get("keys");

        if (keys != null && keys.isArray()) {
          for (JsonNode key : keys) {
            String keyId = key.has("kid") ? key.get("kid").asText() : null;
            if (keyId != null) {
              PublicKey publicKey = parsePublicKey(key);
              if (publicKey != null) {
                keyCache.put(organizationId + ":" + keyId, publicKey);
              }
            }
          }
        }
      } else {
        ourLog.warn(
          "Failed to fetch JWKS for organization {}: HTTP {} Body: {}",
          organizationId,
          response.statusCode(),
          response.body()
        );
      }
    } catch (Exception e) {
      ourLog.error(
        "Failed to refresh JWKS for organization {} from URL {}",
        organizationId,
        keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/certs",
        e
      );
    }
  }

  private PublicKey parsePublicKey(JsonNode jwkNode) {
    try {
      String n = jwkNode.has("n") ? jwkNode.get("n").asText() : null;
      String exponent = jwkNode.has("e") ? jwkNode.get("e").asText() : null;

      if (n == null || exponent == null) {
        return null;
      }

      byte[] nBytes = Base64.getUrlDecoder().decode(n);
      byte[] eBytes = Base64.getUrlDecoder().decode(exponent);

      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(
        new BigInteger(1, nBytes),
        new BigInteger(1, eBytes)
      );
      return keyFactory.generatePublic(keySpec);
    } catch (Exception ex) {
      ourLog.error("Failed to parse public key: {}", ex.getMessage());
      return null;
    }
  }

  private boolean validateSignature(String[] jwtParts, PublicKey publicKey, String alg) {
    try {
      String signatureAlgorithm = toJcaSignatureAlgorithm(alg);
      if (signatureAlgorithm == null) {
        return false;
      }

      Signature verifier = Signature.getInstance(signatureAlgorithm);
      verifier.initVerify(publicKey);
      String signingInput = jwtParts[0] + "." + jwtParts[1];
      verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
      byte[] signature = Base64.getUrlDecoder().decode(jwtParts[2]);
      return verifier.verify(signature);
    } catch (Exception ex) {
      ourLog.warn("JWT signature validation failed: {}", ex.getMessage());
      return false;
    }
  }

  private String toJcaSignatureAlgorithm(String alg) {
    return switch (alg) {
      case "RS256" -> "SHA256withRSA";
      case "RS384" -> "SHA384withRSA";
      case "RS512" -> "SHA512withRSA";
      default -> null;
    };
  }

  private boolean validateExpiration(JsonNode payloadNode) {
    if (!payloadNode.has("exp")) {
      return false;
    }
    long exp = payloadNode.get("exp").asLong();
    return Instant.now().getEpochSecond() < exp;
  }

  private boolean validateIssuer(JsonNode payloadNode, String keycloakUrl, String realm) {
    if (!payloadNode.has("iss")) {
      return false;
    }
    String iss = payloadNode.get("iss").asText();

    String baseDomain = smartProperties.getKeycloakBaseDomain();
    String expectedIssuerFromBase = null;
    if (baseDomain != null && !baseDomain.isBlank()) {
      String lowerDomain = baseDomain.toLowerCase();
      String scheme =
        lowerDomain.startsWith("localhost") ||
          lowerDomain.startsWith("127.0.0.1") ||
          lowerDomain.startsWith("host.docker.internal")
          ? "http://"
          : "https://";
      expectedIssuerFromBase = scheme + baseDomain + "/realms/" + realm;
    }

    String expectedIssuerFromKeycloakUrl = keycloakUrl + "/realms/" + realm;

    // Direct exact match against either expected issuer
    if (iss.equals(expectedIssuerFromBase) || iss.equals(expectedIssuerFromKeycloakUrl)) {
      return true;
    }

    // For local/development, treat localhost, 127.0.0.1, and host.docker.internal as equivalent
    try {
      URI issUri = URI.create(iss);
      URI expectedBaseUri = expectedIssuerFromBase != null ? URI.create(expectedIssuerFromBase) : null;
      URI expectedKeycloakUri = URI.create(expectedIssuerFromKeycloakUrl);

      if (matchesLocalIssuer(issUri, expectedBaseUri) || matchesLocalIssuer(issUri, expectedKeycloakUri)) {
        return true;
      }
    } catch (IllegalArgumentException e) {
      ourLog.warn("Failed to parse issuer URI: {}", iss);
    }

    return false;
  }

  private boolean matchesLocalIssuer(URI actual, URI expected) {
    if (expected == null) {
      return false;
    }

    String actualHost = actual.getHost() != null ? actual.getHost().toLowerCase() : "";
    String expectedHost = expected.getHost() != null ? expected.getHost().toLowerCase() : "";

    boolean hostsEquivalent =
      (isLocalHost(actualHost) && isLocalHost(expectedHost)) || actualHost.equals(expectedHost);

    boolean portsEqual = actual.getPort() == expected.getPort();
    boolean pathsEqual = actual.getPath() != null && actual.getPath().equals(expected.getPath());

    return hostsEquivalent && portsEqual && pathsEqual;
  }

  private boolean isLocalHost(String host) {
    return "localhost".equals(host) ||
      "127.0.0.1".equals(host) ||
      "host.docker.internal".equals(host);
  }

  private List<String> parseScopes(JsonNode payloadNode) {
    if (payloadNode.has("scope")) {
      String scopeStr = payloadNode.get("scope").asText();
      return List.of(scopeStr.split("\\s+"));
    }
    if (payloadNode.has("scp")) {
      if (payloadNode.get("scp").isArray()) {
        return objectMapper.convertValue(
          payloadNode.get("scp"),
          new TypeReference<List<String>>() {}
        );
      }
    }
    return List.of();
  }

  private String decodeBase64Url(String encoded) {
    String padded = encoded + "=".repeat((4 - encoded.length() % 4) % 4);
    String base64 = padded.replace('-', '+').replace('_', '/');
    byte[] decoded = Base64.getDecoder().decode(base64);
    return new String(decoded, StandardCharsets.UTF_8);
  }

  public static class TokenValidationResult {
    private final boolean valid;
    private final String error;
    private final String subject;
    private final List<String> scopes;
    private final String patientId;
    private final String fhirUser;
    private final String encounterId;
    private final JsonNode rawPayload;
    private final String organizationId;

    private TokenValidationResult(boolean valid, String error, String subject,
                                   List<String> scopes, String patientId, String fhirUser,
                                   String encounterId, JsonNode rawPayload, String organizationId) {
      this.valid = valid;
      this.error = error;
      this.subject = subject;
      this.scopes = scopes;
      this.patientId = patientId;
      this.fhirUser = fhirUser;
      this.encounterId = encounterId;
      this.rawPayload = rawPayload;
      this.organizationId = organizationId;
    }

    public static TokenValidationResult failure(String error) {
      return new TokenValidationResult(false, error, null, null, null, null, null, null, null);
    }

    public static TokenValidationResult success(String subject, List<String> scopes,
                                                 String patientId, String fhirUser,
                                                 String encounterId, JsonNode rawPayload, String organizationId) {
      return new TokenValidationResult(true, null, subject, scopes, patientId, fhirUser,
        encounterId, rawPayload, organizationId);
    }

    public boolean isValid() {
      return valid;
    }

    public String getError() {
      return error;
    }

    public String getSubject() {
      return subject;
    }

    public List<String> getScopes() {
      return scopes;
    }

    public String getPatientId() {
      return patientId;
    }

    public String getFhirUser() {
      return fhirUser;
    }

    public String getEncounterId() {
      return encounterId;
    }

    public JsonNode getRawPayload() {
      return rawPayload;
    }

    public String getOrganizationId() {
      return organizationId;
    }
  }
}
