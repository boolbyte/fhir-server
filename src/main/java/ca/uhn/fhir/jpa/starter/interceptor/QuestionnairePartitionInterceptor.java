package ca.uhn.fhir.jpa.starter.interceptor;

import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.api.RestOperationTypeEnum;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.ForbiddenOperationException;
import ca.uhn.fhir.rest.server.servlet.ServletRequestDetails;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Extension;
import org.hl7.fhir.r4.model.Identifier;
import org.hl7.fhir.r4.model.Questionnaire;
import org.hl7.fhir.r4.model.QuestionnaireResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Interceptor that adds a partition identifier to Questionnaire and QuestionnaireResponse resources
 * during creation and filters them during read/search operations.
 */
@Component
@Interceptor
public class QuestionnairePartitionInterceptor {

	private static final Logger ourLog = LoggerFactory.getLogger(
		QuestionnairePartitionInterceptor.class
	);
	private static final String PARTITION_IDENTIFIER_SYSTEM =
		"https://boolbyte.com/questionnaire-partition";
	private static final String DEFAULT_PARTITION_ID = "DEFAULT";
	public static final String ORIGINAL_TENANT_ID_ATTRIBUTE =
		"boolbyte.originalTenantId";

	public QuestionnairePartitionInterceptor() {
		// Constructor
	}

	/**
	 * Hook for handling incoming requests - adds partition identifier and sets tenant to DEFAULT
	 */
	@Hook(Pointcut.SERVER_INCOMING_REQUEST_PRE_HANDLED)
	public void handleIncomingRequest(
		ServletRequestDetails theRequestDetails,
		RestOperationTypeEnum theOperationType
	) {
		IBaseResource resource = theRequestDetails.getResource();

		String resourceType = theRequestDetails.getResourceName();

		ourLog.debug("=== QuestionnairePartitionInterceptor ===");
		ourLog.debug("Resource type: {}", resourceType);
		ourLog.debug("Operation: {}", theOperationType);
		ourLog.debug("Tenant ID (before): {}", theRequestDetails.getTenantId());
		ourLog.debug("Request path: {}", theRequestDetails.getRequestPath());

		// Check if this is a Questionnaire or QuestionnaireResponse operation
		boolean isTargetResourceType =
			resourceType != null &&
			(resourceType.equals("Questionnaire") ||
				resourceType.equals("QuestionnaireResponse"));

		if (isTargetResourceType) {
			// For operations with a resource body, add partition identifier
			if (
				resource != null &&
				(resource instanceof Questionnaire ||
					resource instanceof QuestionnaireResponse)
			) {
				ourLog.debug(
					"Resource: {}, Operation: {}",
					resource,
					theOperationType
				);
				// Handle CREATE, UPDATE, and PATCH operations - add partition identifier
				if (
					theOperationType == RestOperationTypeEnum.CREATE ||
					theOperationType == RestOperationTypeEnum.UPDATE ||
					theOperationType == RestOperationTypeEnum.PATCH
				) {
					addPartitionIdentifier(resource, theRequestDetails);
				}
			}

			// Always route to DEFAULT partition for these resource types
			setRequestTenantToDefault(theRequestDetails, resourceType);
			ourLog.debug("Tenant ID (after): {}", theRequestDetails.getTenantId());
		}
		ourLog.debug("=== End QuestionnairePartitionInterceptor ===");
	}

	/**
	 * Hook for handling read operations - removes partition identifier from responses
	 */
	@Hook(Pointcut.SERVER_OUTGOING_RESPONSE)
	public void handleReadResponse(
		RequestDetails theRequestDetails,
		IBaseResource theResponse
	) {
		if (theResponse != null) {
			// Validate the response has correct partition identifier before removing it
			if (
				theRequestDetails
					.getRestOperationType()
					.equals(RestOperationTypeEnum.READ)
			) {
				String expectedPartitionId = null;
				Object tenantAttribute = theRequestDetails
					.getUserData()
					.get(ORIGINAL_TENANT_ID_ATTRIBUTE);
				if (tenantAttribute instanceof String tenantFromAttribute) {
					expectedPartitionId = tenantFromAttribute;
				}
				if (expectedPartitionId == null || expectedPartitionId.isEmpty()) {
					expectedPartitionId = getPartitionId(theRequestDetails);
				}
				validateResponse(
					theResponse,
					expectedPartitionId
				);
			}
			removePartitionIdentifier(theResponse);
		}
	}

	private void validateResponse(IBaseResource theResponse, String tenantId) {
		if (theResponse.fhirType().equals("Questionnaire")) {
			Questionnaire questionnaire = (Questionnaire) theResponse;

			List<Identifier> identifiers = questionnaire.getIdentifier();
			if (identifiers == null || identifiers.isEmpty()) {
				throw new ca.uhn.fhir.rest.server.exceptions.ResourceNotFoundException(
					"Questionnaire not found"
				);
			}

			// get the identifier with the system and confirm the value is the partition id
			boolean hasCorrectPartition = false;
			for (Identifier identifier : identifiers) {
				if (
					PARTITION_IDENTIFIER_SYSTEM.equals(identifier.getSystem()) &&
					identifier.getValue().equals(tenantId)
				) {
					hasCorrectPartition = true;
					ourLog.debug(
						"Found partition identifier: {}",
						identifier.getValue()
					);
					break;
				}
			}

			if (!hasCorrectPartition) {
				throw new ca.uhn.fhir.rest.server.exceptions.ResourceNotFoundException(
					"Questionnaire not found"
				);
			}
		}

		if (theResponse.fhirType().equals("QuestionnaireResponse")) {
			QuestionnaireResponse response = (QuestionnaireResponse) theResponse;

			List<Extension> identifiers = response.getExtension();
			if (identifiers == null || identifiers.isEmpty()) {
				throw new ca.uhn.fhir.rest.server.exceptions.ResourceNotFoundException(
					"Questionnaire Response not found"
				);
			}

			// get the identifier with the system and confirm the value is the partition id
			boolean hasCorrectPartition = false;
			for (Extension identifier : identifiers) {
				String identifierValue =
					identifier.getValue() != null
						? identifier.getValue().primitiveValue()
						: null;
				if (
					PARTITION_IDENTIFIER_SYSTEM.equals(identifier.getUrl()) &&
					Objects.equals(identifierValue, tenantId)
				) {
					hasCorrectPartition = true;
					ourLog.debug(
						"Found partition identifier: {}",
						identifierValue
					);
					break;
				}
			}

			if (!hasCorrectPartition) {
				throw new ca.uhn.fhir.rest.server.exceptions.ResourceNotFoundException(
					"Questionnaire Response not found"
				);
			}
		}
	}

	/**
	 * Gets the partition ID from the request details or returns DEFAULT
	 */
	private String getPartitionId(RequestDetails requestDetails) {
		String tenantId = requestDetails.getTenantId();
		if (tenantId != null && !tenantId.isEmpty()) {
			return tenantId;
		}
		return DEFAULT_PARTITION_ID;
	}

	/**
	 * Sets the request tenant to DEFAULT after adding partition identifier
	 * Only applies to Questionnaire and QuestionnaireResponse resources
	 */
	private void setRequestTenantToDefault(
		ServletRequestDetails requestDetails,
		String resourceType
	) {
		// Only set tenant to DEFAULT for Questionnaire and QuestionnaireResponse resources
		if (
			resourceType.equals("Questionnaire") ||
			resourceType.equals("QuestionnaireResponse")
		) {
			// Store the original tenant ID for logging purposes
			String originalTenantId = getPartitionId(requestDetails);

			ourLog.debug("Original tenant ID: {}", originalTenantId);

			requestDetails
				.getUserData()
				.put(ORIGINAL_TENANT_ID_ATTRIBUTE, originalTenantId);
			// Set the tenant to DEFAULT
			requestDetails.setTenantId(DEFAULT_PARTITION_ID);

			ourLog.debug(
				"Set request tenant from '{}' to '{}' after adding partition identifier",
				originalTenantId,
				DEFAULT_PARTITION_ID
			);
		}
	}

	// /**
	//  * Checks if a resource has the correct partition identifier
	//  */
	// private boolean hasCorrectPartition(IBaseResource resource, String expectedPartitionId) {
	//     if (resource instanceof Questionnaire questionnaire) {
	//         for (Identifier identifier : questionnaire.getIdentifier()) {
	//             if (PARTITION_IDENTIFIER_SYSTEM.equals(identifier.getSystem()) &&
	//                 expectedPartitionId.equals(identifier.getValue())) {
	//                 return true;
	//             }
	//         }
	//     } else if (resource instanceof QuestionnaireResponse questionnaireResponse) {
	//         return questionnaireResponse.getExtension().stream()
	//             .anyMatch(ext -> PARTITION_IDENTIFIER_SYSTEM.equals(ext.getUrl()) &&
	//                            expectedPartitionId.equals(ext.getValue().toString()));
	//     }
	//     return false;
	// }

	/**
	 * Adds the partition identifier to Questionnaire and QuestionnaireResponse resources
	 */
	private void addPartitionIdentifier(
		IBaseResource resource,
		RequestDetails requestDetails
	) {
		String partitionId = getPartitionId(requestDetails);

		if (resource instanceof Questionnaire questionnaire) {
			addPartitionIdentifierToQuestionnaire(questionnaire, partitionId);
		} else if (
			resource instanceof QuestionnaireResponse questionnaireResponse
		) {
			addPartitionIdentifierToQuestionnaireResponse(
				questionnaireResponse,
				partitionId
			);
		}
	}

	/**
	 * Adds partition identifier to Questionnaire resource
	 */
	private void addPartitionIdentifierToQuestionnaire(
		Questionnaire questionnaire,
		String partitionId
	) {
		// Check if partition identifier already exists
		boolean hasPartitionIdentifier = false;
		for (Identifier identifier : questionnaire.getIdentifier()) {
			if (PARTITION_IDENTIFIER_SYSTEM.equals(identifier.getSystem())) {
				if (!Objects.equals(identifier.getValue(), partitionId)) {
					throw new ForbiddenOperationException(
						"Questionnaire partition identifier mismatch"
					);
				}
				hasPartitionIdentifier = true;
			}
		}

		if (!hasPartitionIdentifier) {
			Identifier partitionIdentifier = new Identifier();
			partitionIdentifier.setSystem(PARTITION_IDENTIFIER_SYSTEM);
			partitionIdentifier.setValue(partitionId);
			questionnaire.addIdentifier(partitionIdentifier);

			ourLog.debug(
				"Added partition identifier '{}' to Questionnaire: {}",
				partitionId,
				questionnaire.getIdElement().getIdPart()
			);
		}
	}

	/**
	 * Adds partition identifier to QuestionnaireResponse resource
	 */
	private void addPartitionIdentifierToQuestionnaireResponse(
		QuestionnaireResponse questionnaireResponse,
		String partitionId
	) {
		// QuestionnaireResponse doesn't have identifiers, so we'll use an extension instead
		// Check if partition extension already exists and enforce strict match
		boolean hasPartitionExtension = false;
		for (Extension ext : questionnaireResponse.getExtension()) {
			if (PARTITION_IDENTIFIER_SYSTEM.equals(ext.getUrl())) {
				String value =
					ext.getValue() != null ? ext.getValue().primitiveValue() : null;
				if (!Objects.equals(value, partitionId)) {
					throw new ForbiddenOperationException(
						"QuestionnaireResponse partition identifier mismatch"
					);
				}
				hasPartitionExtension = true;
			}
		}

		if (!hasPartitionExtension) {
			org.hl7.fhir.r4.model.Extension partitionExtension =
				new org.hl7.fhir.r4.model.Extension();
			partitionExtension.setUrl(PARTITION_IDENTIFIER_SYSTEM);
			partitionExtension.setValue(
				new org.hl7.fhir.r4.model.StringType(partitionId)
			);
			questionnaireResponse.addExtension(partitionExtension);

			ourLog.debug(
				"Added partition extension '{}' to QuestionnaireResponse: {}",
				partitionId,
				questionnaireResponse.getIdElement().getIdPart()
			);
		}
	}

	/**
	 * Removes the partition identifier from Questionnaire and QuestionnaireResponse resources
	 */
	private void removePartitionIdentifier(IBaseResource resource) {
		if (resource instanceof Questionnaire questionnaire) {
			removePartitionIdentifierFromQuestionnaire(questionnaire);
		} else if (
			resource instanceof QuestionnaireResponse questionnaireResponse
		) {
			removePartitionIdentifierFromQuestionnaireResponse(
				questionnaireResponse
			);
		} else if (resource instanceof Bundle bundle) {
			removePartitionIdentifierFromBundle(bundle);
		}
	}

	/**
	 * Removes partition identifier from Questionnaire resource
	 */
	private void removePartitionIdentifierFromQuestionnaire(
		Questionnaire questionnaire
	) {
		List<Identifier> filteredIdentifiers = new ArrayList<>();
		for (Identifier identifier : questionnaire.getIdentifier()) {
			if (!PARTITION_IDENTIFIER_SYSTEM.equals(identifier.getSystem())) {
				filteredIdentifiers.add(identifier);
			}
		}

		questionnaire.setIdentifier(filteredIdentifiers);

		ourLog.debug(
			"Removed partition identifier from Questionnaire: {}",
			questionnaire.getIdElement().getIdPart()
		);
	}

	/**
	 * Removes partition identifier from QuestionnaireResponse resource
	 */
	private void removePartitionIdentifierFromQuestionnaireResponse(
		QuestionnaireResponse questionnaireResponse
	) {
		questionnaireResponse
			.getExtension()
			.removeIf(ext -> PARTITION_IDENTIFIER_SYSTEM.equals(ext.getUrl()));

		ourLog.debug(
			"Removed partition extension from QuestionnaireResponse: {}",
			questionnaireResponse.getIdElement().getIdPart()
		);
	}

	/**
	 * Removes partition identifier from Bundle resources (for search results)
	 */
	private void removePartitionIdentifierFromBundle(Bundle bundle) {
		if (bundle.getEntry() != null) {
			for (Bundle.BundleEntryComponent entry : bundle.getEntry()) {
				if (entry.getResource() != null) {
					removePartitionIdentifier(entry.getResource());
				}
			}
		}
	}
}
