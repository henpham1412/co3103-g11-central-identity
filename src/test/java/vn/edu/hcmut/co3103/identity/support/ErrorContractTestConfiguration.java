package vn.edu.hcmut.co3103.identity.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcBuilderCustomizer;
import org.springframework.context.annotation.Bean;

@TestConfiguration(proxyBeanMethods = false)
public class ErrorContractTestConfiguration {
    @Bean
    MockMvcBuilderCustomizer strictErrorEnvelope() {
        return builder -> builder.alwaysExpect(ErrorResponseAssertions.errorEnvelope());
    }
}
