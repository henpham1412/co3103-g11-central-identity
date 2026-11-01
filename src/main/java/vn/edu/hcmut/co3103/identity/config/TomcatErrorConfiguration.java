package vn.edu.hcmut.co3103.identity.config;

import org.apache.catalina.core.StandardHost;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TomcatErrorConfiguration {

    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> jsonTomcatErrors() {
        return factory -> factory.addContextCustomizers(context ->
                ((StandardHost) context.getParent()).setErrorReportValveClass(JsonErrorReportValve.class.getName()));
    }
}
