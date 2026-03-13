package ca.uhn.fhir.jpa.starter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "boolbyte")
public class BoolbyteProperties {

	private Interceptor interceptor = new Interceptor();

	public Interceptor getInterceptor() {
		return interceptor;
	}

	public void setInterceptor(Interceptor interceptor) {
		this.interceptor = interceptor;
	}

	public static class Interceptor {

		private boolean questionnaire = false;

		public boolean isQuestionnaire() {
			return questionnaire;
		}

		public void setQuestionnaire(boolean questionnaire) {
			this.questionnaire = questionnaire;
		}
	}
}

