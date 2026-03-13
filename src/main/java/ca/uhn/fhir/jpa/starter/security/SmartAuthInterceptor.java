package ca.uhn.fhir.jpa.starter.security;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.i18n.Msg;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.exceptions.ForbiddenOperationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import java.util.List;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.r4.model.IdType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

@Component
public class SmartAuthInterceptor extends AuthorizationInterceptor {

	private static final Logger ourLog = LoggerFactory.getLogger(
		SmartAuthInterceptor.class
	);

	private static final Set<String> VALID_COMPARTMENT_OWNERS = Set.of(
		"Patient",
		"Practitioner",
		"RelatedPerson"
	);

	private final SmartTokenValidationService tokenValidationService;
	private final FhirContext fhirContext;

	private final List<String> publicEndpoints;
	private final AntPathMatcher pathMatcher = new AntPathMatcher();

	public SmartAuthInterceptor(
		SmartTokenValidationService tokenValidationService,
		SmartProperties smartProperties,
		FhirContext fhirContext,
		Environment environment
	) {
		this.tokenValidationService = tokenValidationService;
		this.fhirContext = fhirContext;
		String[] endpoints = environment.getProperty(
			"hapi.fhir.security.smart.public-endpoints",
			String[].class,
			smartProperties.getPublicEndpoints().toArray(new String[0])
		);
		this.publicEndpoints = List.of(endpoints);
	}

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
		String requestPath = theRequestDetails.getRequestPath();

		if (isPublicEndpoint(requestPath)) {
			return new RuleBuilder().allowAll().build();
		}

		String authHeader = theRequestDetails.getHeader("Authorization");

		if (StringUtils.isBlank(authHeader)) {
			ourLog.warn(
				"No Authorization header found for request: {}",
				requestPath
			);
			throw new AuthenticationException(
				Msg.code(645) + "Missing Authorization header"
			);
		}

		SmartTokenValidationService.TokenValidationResult validationResult =
			tokenValidationService.validateToken(authHeader);

		if (!validationResult.isValid()) {
			ourLog.warn(
				"Token validation failed: {}",
				validationResult.getError()
			);
			throw new AuthenticationException(
				Msg.code(646) + "Invalid token: " + validationResult.getError()
			);
		}

		ourLog.debug(
			"SMART auth for request {} scopes: {}",
			requestPath,
			validationResult.getScopes()
		);

		List<SmartScopeParser.ParsedScope> parsedScopes =
			SmartScopeParser.parseScopes(validationResult.getScopes());

		List<SmartScopeParser.ParsedScope> resourceScopes =
			SmartScopeParser.filterResourceScopes(parsedScopes);

		ourLog.debug(
			"SMART auth for request {} parsed resource scopes: {}",
			requestPath,
			resourceScopes
		);

		if (resourceScopes.isEmpty()) {
			ourLog.warn("No resource scopes found in token");
			throw new ForbiddenOperationException(
				Msg.code(647) + "No valid scopes found"
			);
		}

		RuleBuilder ruleBuilder = new RuleBuilder();

		String patientId = validationResult.getPatientId();
		String userId = validationResult.getFhirUser();

		// Detect whether this incoming request is an operation call.
		// We keep this simple and robust by checking for "$" in the request path
		// (server ops are "/$op", type ops are "/Resource/$op", instance ops are "/Resource/{id}/$op").
		boolean isOperationRequest = false;
		if (requestPath != null) {
			String rp = requestPath;
			isOperationRequest =
				rp.contains("/$") || rp.startsWith("$") || rp.contains("/%24");
		}

		for (SmartScopeParser.ParsedScope scope : resourceScopes) {
			applyScopeRules(
				ruleBuilder,
				scope,
				patientId,
				userId,
				requestPath,
				isOperationRequest
			);
		}

		ruleBuilder.denyAll();

		return ruleBuilder.build();
	}

	private void applyScopeRules(
		RuleBuilder ruleBuilder,
		SmartScopeParser.ParsedScope scope,
		String patientId,
		String userId,
		String requestPath,
		boolean isOperationRequest
	) {
		String resourceType = scope.getResourceType();
		boolean allowRead = scope.allowsRead();
		boolean allowWrite = scope.allowsWrite();

		if (resourceType != null && resourceType.equals("*")) {
			resourceType = null;
		}

		SmartScopeParser.ScopeContext context = scope.getContext();

		if (context == SmartScopeParser.ScopeContext.SYSTEM) {
			/*
			 * Map system scopes to resource-level and operation-level rules.
			 *
			 * For this server we treat system scopes as full access for the
			 * resources they cover:
			 * - system/*.*  => all resources, all operations
			 * - system/Resource.* => that resource type, all operations
			 *
			 * IMPORTANT: every rule chain MUST end with .andThen() so the
			 * RuleBuilder materializes it before the next rule is started.
			 */

			if (resourceType == null) {
				if (allowRead) {
					ruleBuilder.allow().read().allResources().withAnyId().andThen();
				}
				if (allowWrite) {
					ruleBuilder.allow().write().allResources().withAnyId().andThen();
				}

				if (isOperationRequest && (allowRead || allowWrite)) {
					ruleBuilder.allow().operation().withAnyName().onServer();
				}
			} else {
				Class<? extends IBaseResource> resourceClass = getResourceClass(
					resourceType
				);
				if (resourceClass != null) {
					if (allowRead) {
						ruleBuilder.allow().read().resourcesOfType(resourceClass).withAnyId().andThen();
						if (isOperationRequest) {
							ruleBuilder
								.allow()
								.operation()
								.withAnyName()
								.onType(resourceClass);
						}
					}
					if (allowWrite) {
						ruleBuilder.allow().write().resourcesOfType(resourceClass).withAnyId().andThen();
						if (isOperationRequest) {
							ruleBuilder
								.allow()
								.operation()
								.withAnyName()
								.onType(resourceClass);
						}
					}

					if (isOperationRequest && requestPath != null) {
						String pattern = "/" + resourceType + "/";
						int idx = requestPath.indexOf(pattern);
						if (idx != -1) {
							int start = idx + pattern.length();
							int end = requestPath.indexOf('/', start);
							if (end == -1) {
								end = requestPath.length();
							}
							String seg = requestPath.substring(start, end);
							if (
								seg != null && !seg.isEmpty() && !seg.startsWith("$")
							) {
								IdType instanceRef = new IdType(resourceType, seg);
								ruleBuilder
									.allow()
									.operation()
									.withAnyName()
									.onInstance(instanceRef);
							}
						}
					}
				}
			}
		} else if (context == SmartScopeParser.ScopeContext.PATIENT) {
			if (patientId == null) {
				ourLog.warn(
					"Patient scope requested but no patient context available"
				);
				return;
			}

			IdType patientReference = new IdType("Patient", patientId);

			if (resourceType == null) {
				if (allowRead) {
					ruleBuilder
						.allow()
						.read()
						.allResources()
						.inCompartment("Patient", patientReference)
						.andThen();
				}
				if (allowWrite) {
					ruleBuilder
						.allow()
						.write()
						.allResources()
						.inCompartment("Patient", patientReference)
						.andThen();
				}
			} else {
				Class<? extends IBaseResource> resourceClass = getResourceClass(
					resourceType
				);
				if (resourceClass != null) {
					if (allowRead) {
						ruleBuilder
							.allow()
							.read()
							.resourcesOfType(resourceClass)
							.inCompartment("Patient", patientReference)
							.andThen();
					}
					if (allowWrite) {
						ruleBuilder
							.allow()
							.write()
							.resourcesOfType(resourceClass)
							.inCompartment("Patient", patientReference)
							.andThen();
					}
				}
			}

			if (
				isOperationRequest &&
				allowRead &&
				(resourceType == null || "Patient".equals(resourceType))
			) {
				ruleBuilder
					.allow()
					.operation()
					.withAnyName()
					.onInstance(patientReference);
			}
		} else if (context == SmartScopeParser.ScopeContext.USER) {
			String compartmentId = null;
			String compartmentType = "Patient";
			IdType userReference = null;

			if (userId != null) {
				IdType userRef = parseFhirUser(userId);
				if (userRef != null) {
					compartmentType = userRef.getResourceType();
					if (compartmentType == null || compartmentType.isEmpty()) {
						compartmentType = "Patient";
					}
					compartmentId = userRef.getIdPart();
					userReference = new IdType(compartmentType, compartmentId);
				} else {
					ourLog.debug("Parsed fhirUser is null for fhirUser: {}", userId);
				}
			}

			if (compartmentId == null) {
				ourLog.warn(
					"USER scope present but no valid fhirUser available to derive compartment for scope: {}",
					scope
				);
				return;
			}

			if (
				compartmentType == null ||
				!VALID_COMPARTMENT_OWNERS.contains(compartmentType)
			) {
				ourLog.warn(
					"Derived compartment type '{}' is not a recognized compartment owner. Falling back to 'Patient' for scope: {}",
					compartmentType,
					scope
				);
				compartmentType = "Patient";
			}

			IdType compartmentReference = new IdType(
				compartmentType,
				compartmentId
			);

			if (resourceType == null) {
				if (allowRead) {
					ruleBuilder
						.allow()
						.read()
						.allResources()
						.inCompartment(compartmentType, compartmentReference)
						.andThen();
				}
				if (allowWrite) {
					ruleBuilder
						.allow()
						.write()
						.allResources()
						.inCompartment(compartmentType, compartmentReference)
						.andThen();
				}
			} else {
				Class<? extends IBaseResource> resourceClass = getResourceClass(
					resourceType
				);
				if (resourceClass != null) {
					if (allowRead) {
						ruleBuilder
							.allow()
							.read()
							.resourcesOfType(resourceClass)
							.inCompartment(compartmentType, compartmentReference)
							.andThen();
					}
					if (allowWrite) {
						ruleBuilder
							.allow()
							.write()
							.resourcesOfType(resourceClass)
							.inCompartment(compartmentType, compartmentReference)
							.andThen();
					}
				}
			}

			if (
				isOperationRequest &&
				allowRead &&
				userReference != null &&
				(resourceType == null || resourceType.equals(compartmentType))
			) {
				ruleBuilder
					.allow()
					.operation()
					.withAnyName()
					.onInstance(userReference);
			}
		} else {
			// Log unknown/unsupported scope contexts so they are visible in logs
			ourLog.warn(
				"Unrecognized SMART scope context: {} for scope: {}",
				context,
				scope
			);
		}
	}

	private IdType parseFhirUser(String fhirUser) {
		try {
			if (fhirUser.contains("/")) {
				return new IdType(fhirUser);
			}
			return new IdType("Patient", fhirUser);
		} catch (Exception e) {
			ourLog.warn("Failed to parse fhirUser: {}", fhirUser);
			return null;
		}
	}

	private Class<? extends IBaseResource> getResourceClass(
		String resourceType
	) {
		try {
			return fhirContext
				.getResourceDefinition(resourceType)
				.getImplementingClass();
		} catch (Exception e) {
			ourLog.warn("Unknown resource type: {}", resourceType);
			return null;
		}
	}

	private boolean isPublicEndpoint(String requestPath) {
		if (requestPath == null) {
			return false;
		}

		// Keep root as public
		if (requestPath.equals("/") || requestPath.equals("")) {
			return true;
		}

		// Normalize requestPath to remove a trailing slash (except for root)
		String normalizedRequestPath = requestPath;
		if (
			normalizedRequestPath.endsWith("/") &&
			normalizedRequestPath.length() > 1
		) {
			normalizedRequestPath = normalizedRequestPath.substring(
				0,
				normalizedRequestPath.length() - 1
			);
		}

		// Match against configured public endpoints (supports Ant-style patterns)
		for (String pattern : publicEndpoints) {
			if (pattern == null) {
				continue;
			}
			String p = pattern.trim();
			if (p.isEmpty()) {
				continue;
			}
			// Normalize pattern similarly
			if (p.endsWith("/") && p.length() > 1) {
				p = p.substring(0, p.length() - 1);
			}
			if (pathMatcher.match(p, normalizedRequestPath)) {
				return true;
			}
		}

		return false;
	}
}
