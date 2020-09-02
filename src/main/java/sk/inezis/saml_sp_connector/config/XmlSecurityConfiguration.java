package sk.inezis.saml_sp_connector.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;

@Configuration
public class XmlSecurityConfiguration {

    @Value("${org.apache.xml.security.resource.config}")
    private String configurationPath;

    @PostConstruct
    public void init() {
        System.setProperty("org.apache.xml.security.resource.config", configurationPath);
    }
}
