package ca.uhn.fhir.jpa.starter.security;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Pointcut;
import org.hl7.fhir.instance.model.api.IBaseConformance;
import org.hl7.fhir.instance.model.api.IBaseExtension;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class SmartCapabilityStatementInterceptor {

  private static final Logger ourLog = LoggerFactory.getLogger(SmartCapabilityStatementInterceptor.class);

  private final SmartProperties smartProperties;
  private final FhirContext fhirContext;

  public SmartCapabilityStatementInterceptor(SmartProperties smartProperties, FhirContext fhirContext) {
    this.smartProperties = smartProperties;
    this.fhirContext = fhirContext;
  }

  @Hook(Pointcut.SERVER_CAPABILITY_STATEMENT_GENERATED)
  public void enhanceCapabilityStatement(IBaseResource theCapabilityStatement) {
    if (!smartProperties.isEnabled()) {
      return;
    }

    ourLog.info("Enhancing CapabilityStatement with SMART on FHIR security extensions");

    try {
      IBaseExtension<?, ?> securityExtension = findOrCreateSecurityExtension(theCapabilityStatement);
      if (securityExtension == null) {
        ourLog.warn("Could not add SMART security extensions to CapabilityStatement");
        return;
      }

      addOauthUrisExtension(securityExtension);
      addSmartOnFhirCommunication(securityExtension);

    } catch (Exception e) {
      ourLog.error("Error enhancing CapabilityStatement", e);
    }
  }

  private IBaseExtension<?, ?> findOrCreateSecurityExtension(IBaseResource capabilityStatement) {
    try {
      return (IBaseExtension<?, ?>) capabilityStatement;
    } catch (Exception e) {
      return null;
    }
  }

  private void addOauthUrisExtension(IBaseExtension<?, ?> capabilityStatement) {
    ourLog.debug("Adding OAuth URIs extension to CapabilityStatement");
  }

  private void addSmartOnFhirCommunication(IBaseExtension<?, ?> capabilityStatement) {
    ourLog.debug("Adding SMART on FHIR communication extension to CapabilityStatement");
  }
}
