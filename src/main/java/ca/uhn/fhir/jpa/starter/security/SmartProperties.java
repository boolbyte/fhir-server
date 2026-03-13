package ca.uhn.fhir.jpa.starter.security;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "hapi.fhir.security.smart")
public class SmartProperties {

	private boolean enabled = true;
	private String keycloakBaseDomain = "auth.boolbyte.com";
	private String realm = "smart-fhir";
	private String baseDomain = "fhir.boolbyte.com";
	private String defaultOrganization = "default";
	private String systemClientId;

	/**
	 * Public endpoints that do not require authentication.
	 * Can be overridden via configuration: hapi.fhir.security.smart.public-endpoints
	 */
	private List<String> publicEndpoints = List.of(
		"/metadata",
		"/health",
		"/fhir/metadata",
		"/fhir/health",
		"/.well-known/smart-configuration",
		"/fhir/swagger-ui/**",
		"/fhir/api-docs/**",
		"/actuator/health"
	);

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getKeycloakBaseDomain() {
		return keycloakBaseDomain;
	}

	public void setKeycloakBaseDomain(String keycloakBaseDomain) {
		this.keycloakBaseDomain = keycloakBaseDomain;
	}

	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	public String getBaseDomain() {
		return baseDomain;
	}

	public void setBaseDomain(String baseDomain) {
		this.baseDomain = baseDomain;
	}

	public String getDefaultOrganization() {
		return defaultOrganization;
	}

	public void setDefaultOrganization(String defaultOrganization) {
		this.defaultOrganization = defaultOrganization;
	}

	public String getSystemClientId() {
		return systemClientId;
	}

	public void setSystemClientId(String systemClientId) {
		this.systemClientId = systemClientId;
	}

	public List<String> getPublicEndpoints() {
		return publicEndpoints;
	}

	public void setPublicEndpoints(List<String> publicEndpoints) {
		this.publicEndpoints = publicEndpoints;
	}

	public String getKeycloakUrl(String organizationId) {
		String lowerDomain = keycloakBaseDomain.toLowerCase();
		String scheme =
			lowerDomain.startsWith("localhost") ||
					lowerDomain.startsWith("127.0.0.1") ||
					lowerDomain.startsWith("host.docker.internal")
				? "http://"
				: "https://";

		if (
			organizationId == null || organizationId.equals(defaultOrganization)
		) {
			return scheme + keycloakBaseDomain;
		}
		return scheme + organizationId + "." + keycloakBaseDomain;
	}
}
