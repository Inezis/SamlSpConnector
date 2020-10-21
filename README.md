
# SAML Service Provider Connector (SAML SPC)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

##Table of Contents
  * [Table of Contents](#table-ofcontents)
  * [General description](#general-description)
  * [Architecture](#architecture)
  * [SAML SP Connector API](#saml-sp-connector-api)
  * [Github](#github)
  * [Dependencies](#dependencies)
  * [Build and usage](#build-and-usage)
  * [Settings](#settings)
    * [Properties File](#properties-file)
    * [OneLogin's SAML Java Toolkit Properties File](#onelogins-saml-java-toolkit-properties-file)
  
## General description
SAML Service Provider Connector is an open source Java library that allows you to easily implement a Service Provider (SP) by encapsulating SAML communication with an Identity Provider (IdP).

All sensitive cryptographic operations on the service provider's side are performed by SAML SPC in Azure KeyVault:
 - SAML AuthRequest signing
 - SAML Assertion decryption

SAML communication on the service provider's side (preparation of SAML Authentication Request, SAML Response validation) is handled using an SAML Java open source library provided by OneLogin Inc.

The open source SAML SPC software is provided and supported by inezis s.r.o.


## Architecture

![SAML SP Connector architecture](doc/SamlSPConnector.png?raw=true)

 1. The user tries to access the protected resource on the SP website.
 2. SP requests the SAML SPC to generate SAML Authentication Request by calling ***generateRequest***.
 3. SAML SPC generates the SAML Authentication Request using the *onelogin java-saml library*. SAML SPC uses its private key stored in Azure KeyVault to sign a SAML Authentication Request.
 4. SAML SPC returns a signed SAML Authentication Request (as a base64 encoded string in json).
 5. SP sends the signed SAML Authentication Request to Identity Provider (IdP).
 6. IdP authenticates the user and sends the signed SAML response containing encrypted SAML Assertion back to SP. The encrypted SAML Assertion contains the user identity data.
 7. SP requests the SAML SPC to validate and parse the received SAML Response by calling ***parseResponse***.
 8. SAML SPC verifies the SAML Response Signature and decrypts the SAML Assertion using its private key stored in Azure KeyVault.
 10. SAML SPC returns the parsed SAML Assertion attributes (mime type of response is _application/json_).

## SAML SP Connector API
The specification of the SAML SP Connector API is available as OpenAPI here: [SAML SPC API Specification](https://generator.swagger.io/?url=https://raw.githubusercontent.com/Inezis/SamlSpConnector/master/doc/openapi.yaml)

## Github
SAML SP Connector is hosted on github:
* Master repo: https://github.com/Inezis/SamlSpConnector/tree/master/
* Master repo for OneLogin's SAML Java Toolkit: https://github.com/onelogin/java-saml/tree/master


## Dependencies
The project was tested with OpenJDK Java 14. The Java version can be changed in pom.xml.
For Java 8 the [Java Cryptography Extension (JCE)](https://en.wikipedia.org/wiki/Java_Cryptography_Extension) is required. If you don't have it, download the version of [jce-8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html), unzip it, and drop its content at *${java.home}/jre/lib/security/*. 


## Build and usage
This project uses Maven. A simple build can be done with the following command:

```
mvn clean package
```

This command produces Spring Boot JAR file into output directory, e.g. _target/saml_sp_connector-1.0.0.jar_.
SAML SPC can be then run with the following command:

```
java -jar /opt/saml-sp-connector/saml_sp_connector-1.0.0.jar
```

By default, SAML SPC connector listens on port 8080. This can be customized via _server.port_ property (see [Settings](#settings)).
Externalization of properties files can be done by standard Spring Boot means (see [Spring Boot Externalized Configuration](https://docs.spring.io/spring-boot/docs/current/reference/html/spring-boot-features.html#boot-features-external-config)), e.g.:
```
export SPRING_CONFIG_LOCATION=file:///opt/saml-sp-connector/conf/
java -jar /opt/saml-sp-connector/saml_sp_connector-1.0.0.jar
```


## Settings
First of all we need to configure the toolkit. The SP's info, the IdP's info, and in some cases, configuration for advanced security issues, such as signatures and encryption.

### Properties File
The settings are defined in *application.properties* file.
Here are the  properties to be defined in the settings file:

```properties
server.port=8080
org.apache.xml.security.resource.config=/config/xml/xmlsecurity.xml

# ===============================
# = java-saml
# ===============================
onelogin.saml.properties.location-type=CLASSPATH
onelogin.saml.properties.path=onelogin.saml.properties

# ===============================
# = Azure KeyVault
# ===============================
security.key-vault.application.id=
security.key-vault.application.secret=
security.key-vault.key.rsa.identifier=https://hsm-keys.vault.azure.net/keys/REPLACE_ME/REPLACE_ME
security.key-vault.cert.sign.identifier=https://hsm-keys.vault.azure.net/certificates/REPLACE_ME/REPLACE_ME
```
**Important:** You can customize the cryptographic algorithms in the configuration file specified via the property *org.apache.xml.security.resource.config* 

### OneLogin's SAML Java Toolkit Properties File
The SAML Java Toolkit settings are defined in the *onelogin.saml.properties* file, more details about these settings can be found here: https://github.com/onelogin/java-saml/#Settings

