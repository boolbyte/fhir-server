package ca.uhn.fhir.jpa.starter.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class SmartScopeParser {

  private static final Set<String> IDENTITY_SCOPES = Set.of(
    "openid", "fhirUser", "launch", "launch/patient", "launch/encounter",
    "offline_access", "online_access"
  );

  public static List<ParsedScope> parseScopes(List<String> scopes) {
    List<ParsedScope> parsed = new ArrayList<>();

    if (scopes == null) {
      return parsed;
    }

    for (String scope : scopes) {
      ParsedScope parsedScope = parseScope(scope);
      if (parsedScope != null) {
        parsed.add(parsedScope);
      }
    }

    return parsed;
  }

  public static ParsedScope parseScope(String scope) {
    if (scope == null || scope.isBlank()) {
      return null;
    }

    scope = scope.trim();

    if (IDENTITY_SCOPES.contains(scope) || scope.startsWith("launch/")) {
      return new ParsedScope(ScopeContext.IDENTITY, scope, null, null);
    }

    if (scope.startsWith("system/")) {
      return parseSystemScope(scope);
    } else if (scope.startsWith("patient/")) {
      return parsePatientScope(scope);
    } else if (scope.startsWith("user/")) {
      return parseUserScope(scope);
    }

    return null;
  }

  private static ParsedScope parseSystemScope(String scope) {
    String[] parts = scope.split("/");
    if (parts.length < 2) {
      return null;
    }

    ResourceAndPermission resourceAndPermission = extractResourceAndPermission(parts);

    return new ParsedScope(
      ScopeContext.SYSTEM,
      resourceAndPermission.resourceType(),
      resourceAndPermission.permission(),
      null
    );
  }

  private static ParsedScope parsePatientScope(String scope) {
    String[] parts = scope.split("/");
    if (parts.length < 2) {
      return null;
    }

    ResourceAndPermission resourceAndPermission = extractResourceAndPermission(parts);

    return new ParsedScope(
      ScopeContext.PATIENT,
      resourceAndPermission.resourceType(),
      resourceAndPermission.permission(),
      null
    );
  }

  private static ParsedScope parseUserScope(String scope) {
    String[] parts = scope.split("/");
    if (parts.length < 2) {
      return null;
    }

    ResourceAndPermission resourceAndPermission = extractResourceAndPermission(parts);

    return new ParsedScope(
      ScopeContext.USER,
      resourceAndPermission.resourceType(),
      resourceAndPermission.permission(),
      null
    );
  }

  private static ResourceAndPermission extractResourceAndPermission(String[] parts) {
    String resourceAndMaybePermission = parts[1];
    String resourceType = resourceAndMaybePermission;
    String permission = null;

    int dotIndex = resourceAndMaybePermission.indexOf('.');
    if (dotIndex > 0 && dotIndex < resourceAndMaybePermission.length() - 1) {
      resourceType = resourceAndMaybePermission.substring(0, dotIndex);
      permission = normalizePermission(
        resourceAndMaybePermission.substring(dotIndex + 1)
      );
    } else if (parts.length >= 3) {
      permission = normalizePermission(parts[2]);
    }

    if (permission == null) {
      permission = "read";
    }

    return new ResourceAndPermission(resourceType, permission);
  }

  private static String normalizePermission(String permissionValue) {
    if (permissionValue == null || permissionValue.isBlank()) {
      return null;
    }

    String perm = permissionValue.trim();
    if ("*".equals(perm)) {
      return "*";
    }
    if (perm.endsWith(".read")) {
      return "read";
    }
    if (perm.endsWith(".write")) {
      return "write";
    }
    if ("read".equals(perm)) {
      return "read";
    }
    if ("write".equals(perm)) {
      return "write";
    }
    // SMART v2 granular permissions (e.g. rs, cruds) collapsed to read/write model.
    if (perm.matches("[A-Za-z]+")) {
      String lowerPerm = perm.toLowerCase();
      boolean read = lowerPerm.contains("r") || lowerPerm.contains("s");
      boolean write =
        lowerPerm.contains("c") ||
        lowerPerm.contains("u") ||
        lowerPerm.contains("d");
      if (read && write) {
        return "*";
      }
      if (read) {
        return "read";
      }
      if (write) {
        return "write";
      }
    }
    return perm;
  }

  private record ResourceAndPermission(String resourceType, String permission) {}
  
  private static String toSmartScopePermission(String permission) {
    if (permission == null) {
      return null;
    }
    if ("*".equals(permission)) {
      return "*";
    }
    return permission;
  }

  public static boolean isIdentityScope(String scope) {
    return IDENTITY_SCOPES.contains(scope) || scope.startsWith("launch/");
  }

  public static List<ParsedScope> filterResourceScopes(List<ParsedScope> scopes) {
    return scopes.stream()
      .filter(s -> s.getContext() != ScopeContext.IDENTITY)
      .collect(Collectors.toList());
  }

  public enum ScopeContext {
    SYSTEM,
    PATIENT,
    USER,
    IDENTITY
  }

  public static class ParsedScope {
    private final ScopeContext context;
    private final String resourceType;
    private final String permission;
    private final String patientId;

    public ParsedScope(ScopeContext context, String resourceType, String permission, String patientId) {
      this.context = context;
      this.resourceType = resourceType;
      this.permission = permission;
      this.patientId = patientId;
    }

    public ScopeContext getContext() {
      return context;
    }

    public String getResourceType() {
      return resourceType;
    }

    public String getPermission() {
      return permission;
    }

    public String getPatientId() {
      return patientId;
    }

    public boolean allowsRead() {
      return permission == null || permission.equals("read") || permission.equals("*");
    }

    public boolean allowsWrite() {
      return permission == null || permission.equals("write") || permission.equals("*");
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      switch (context) {
        case SYSTEM -> sb.append("system/");
        case PATIENT -> sb.append("patient/");
        case USER -> sb.append("user/");
        default -> sb.append("identity/");
      }
      if (resourceType != null) {
        sb.append(resourceType);
        if (permission != null) {
          sb.append(".").append(toSmartScopePermission(permission));
        }
      }
      return sb.toString();
    }
  }
}
