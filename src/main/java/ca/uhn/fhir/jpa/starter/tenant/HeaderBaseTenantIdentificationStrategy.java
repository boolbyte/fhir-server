package ca.uhn.fhir.jpa.starter.tenant;

import ca.uhn.fhir.jpa.starter.AppProperties;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.api.server.SystemRequestDetails;
import ca.uhn.fhir.rest.server.tenant.ITenantIdentificationStrategy;
import ca.uhn.fhir.util.UrlPathTokenizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HeaderBaseTenantIdentificationStrategy
	implements ITenantIdentificationStrategy
{

	private static final Logger ourLog = LoggerFactory.getLogger(
		HeaderBaseTenantIdentificationStrategy.class
	);
	private AppProperties appProperties;

	public HeaderBaseTenantIdentificationStrategy(AppProperties appProperties) {
		this.appProperties = appProperties;
	}

	@Override
	public void extractTenant(
		UrlPathTokenizer theUrlPathTokenizer,
		RequestDetails theRequestDetails
	) {
		String tenantId = null;

		boolean isSystemRequest = (theRequestDetails instanceof
				SystemRequestDetails);

		if (isSystemRequest) {
			tenantId = "DEFAULT";
			theRequestDetails.setTenantId(tenantId);
			ourLog.trace("No tenant ID found for system request; using DEFAULT.");
		}

		// Primary header from configuration
		String primaryHeader = appProperties
			.getTenant()
			.getTenant_identification_header();
		if (primaryHeader != null && !primaryHeader.trim().isEmpty()) {
			tenantId = theRequestDetails.getHeader(primaryHeader);
		}

		if (tenantId == null || tenantId.trim().isEmpty()) {
			tenantId = "DEFAULT";
			ourLog.trace("No tenant ID found for request; using DEFAULT.");
		}

		theRequestDetails.setTenantId(tenantId);
	}

	@Override
	public String massageServerBaseUrl(
		String theServerBaseUrl,
		RequestDetails theRequestDetails
	) {
		// For header-based partitioning, we don't modify the server base URL
		return theServerBaseUrl;
	}

	@Override
	public String resolveRelativeUrl(
		String theRelativeUrl,
		RequestDetails theRequestDetails
	) {
		// For header-based partitioning, we don't modify relative URLs
		// since the tenant is identified by headers, not URL structure
		return theRelativeUrl;
	}
}
