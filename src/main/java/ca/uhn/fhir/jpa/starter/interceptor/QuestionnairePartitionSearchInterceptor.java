package ca.uhn.fhir.jpa.starter.interceptor;

import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.api.RestOperationTypeEnum;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Interceptor that adds partition identifier search parameters to database queries
 * for Questionnaire and QuestionnaireResponse resources.
 */
@Component
@Interceptor
public class QuestionnairePartitionSearchInterceptor {

	private static final Logger ourLog = LoggerFactory.getLogger(
		QuestionnairePartitionSearchInterceptor.class
	);
	private static final String PARTITION_IDENTIFIER_SYSTEM =
		"https://boolbyte.com/questionnaire-partition";
	private static final String DEFAULT_PARTITION_ID = "DEFAULT";

	@Hook(Pointcut.SERVER_INCOMING_REQUEST_POST_PROCESSED)
	public void handleIncomingRequest(RequestDetails theRequestDetails) {
		String resourceType = theRequestDetails.getResourceName();
		RestOperationTypeEnum operationType =
			theRequestDetails.getRestOperationType();

		ourLog.debug(
			"Resource type: {}, Operation type: {}, Tenant ID: {}",
			resourceType,
			operationType,
			theRequestDetails.getTenantId()
		);

		if (
			operationType != RestOperationTypeEnum.SEARCH_TYPE &&
			operationType != RestOperationTypeEnum.SEARCH_SYSTEM
		) {
			return;
		}

		if (resourceType == null || resourceType.isEmpty()) {
			return;
		}

		if (
			resourceType.equals("Questionnaire") ||
			resourceType.equals("QuestionnaireResponse")
		) {
			String partitionId = null;
			Object tenantAttribute = theRequestDetails
				.getUserData()
				.get(QuestionnairePartitionInterceptor.ORIGINAL_TENANT_ID_ATTRIBUTE);
			if (tenantAttribute instanceof String tenantFromAttribute) {
				partitionId = tenantFromAttribute;
			}
			if (partitionId == null || partitionId.isEmpty()) {
				partitionId = theRequestDetails.getTenantId();
			}
			if (partitionId == null || partitionId.isEmpty()) {
				partitionId = DEFAULT_PARTITION_ID;
			}

			ourLog.debug(
				"Adding partition search parameter for resource type: {} (partitionId={})",
				resourceType,
				partitionId
			);
			addPartitionSearchParameter(
				theRequestDetails,
				partitionId
			);
		}
	}

	private void addPartitionSearchParameter(
		RequestDetails theRequestDetails,
		String partitionId
	) {
		// Create a new modifiable map from the existing parameters
		Map<String, String[]> parameters = new HashMap<>(
			theRequestDetails.getParameters()
		);

		if (theRequestDetails.getResourceName().equals("Questionnaire")) {
			parameters.put(
				"identifier",
				new String[] { PARTITION_IDENTIFIER_SYSTEM + "|" + partitionId }
			);
		}

		if (theRequestDetails.getResourceName().equals("QuestionnaireResponse")) {
			parameters.put(
				"extension",
				new String[] { PARTITION_IDENTIFIER_SYSTEM + "|" + partitionId }
			);
		}

		ourLog.debug("Parameters: {}", parameters);

		theRequestDetails.setParameters(parameters);
	}
}
