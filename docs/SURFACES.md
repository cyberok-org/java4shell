# Product and library surfaces

This is a **call-path inventory**, not a list of products with demonstrated remote
DoS or RCE. Every row additionally requires an affected HotSpot build, the CPU
features, effective flags and application reachability. "Pre-auth" means decode
can precede credential verification in the named path; deployment policy may
still limit who reaches that path.

Evidence labels:

- **Product lab:** the campaign exercised the path in the named configuration;
  those runs did not observe a JVM crash. This is not a byte-level memory trace.
- **Source/bytecode:** campaign review located the call; this publication does
  not claim a new full product retest.
- **Candidate:** insufficient or conflicting evidence; not a confirmed exposure.

All confirmed paths below use **one-argument decoding/new destination arrays**.
The higher-priority caller-supplied reused-buffer form was not found in the
reviewed platform call sites. Custom application code still needs review.

## Servers and applications

| Component | Reviewed path / version scope | Evidence |
| --- | --- | --- |
| Tomcat | `BasicAuthenticator.BasicCredentials.parseBase64`; switch to JDK decoder at 9.0.89 / 10.1.23, also 11.x | Source; lab 9.0.89 and 11.x |
| Tomcat HTTP/2 | `Http2Protocol.accept` decodes `HTTP2-Settings`; structured-field binary values are another reviewed path | Source; lab 11.x with relevant HTTP/2 configuration |
| Spring Security | Servlet `BasicAuthenticationConverter`, verified 5.8/6.x and reviewed main; do not infer all earlier 5.x | Source; Spring Boot 3.2.5 / Security 6.2.x lab |
| Elasticsearch | `UsernamePasswordToken.extractToken` Basic; API-key parsing; separate SAML IdP signature path | Source; Basic lab 8.11.4/JDK 21.0.1 |
| Jetty | `BasicAuthenticator`, reviewed 9.4+ and later branches; exact deployment branch must be checked | Source |
| Jenkins | `BasicHeaderProcessor` / `BasicAuthenticationFilter` | Source |
| Solr | `BasicAuthPlugin` when Basic authentication is configured; release floor not established here | Source |
| Zimbra | Container Jetty authentication path in reviewed 10.x configurations; not every Zimbra codec | Source |
| Jira / Confluence DC | Seraph `SecurityUtils.decodeBasicAuthorizationCredentials`; reviewed Seraph 4.0.4/5.0.7/6.0.2 | Bytecode |
| Neo4j | `AuthorizationHeaders`, server HTTP authentication / query API paths | Source |
| SonarQube | `BasicAuthentication` called during request authentication | Source |
| Openfire | `SASLAuthentication` initial response in reviewed 4.9+/5.x; the 4.8 implementation differs | Source |
| Kafka | SCRAM `ClientFinalMessage` channel-binding/proof fields in `ScramMessages` | Source; protocol state/configuration affects reachability |
| NiFi | `ProxiedEntitiesUtils` handling the encoded proxied-entity chain | Source; review trust/configuration boundaries |
| Apache James | `SaslCodec.decodeClientResponse` used by authentication handlers | Source; JVM version remains decisive |
| ActiveMQ Classic | `WebClient` authentication handling in web/REST surface; not a claim about all messaging protocols | Source |
| JDK HTTP server / Jolokia agent | `com.sun.net.httpserver.BasicAuthenticator`; reviewed Jolokia agent subclass | Source; other Jolokia packaging differs |

## Libraries and frameworks

| Component | Reviewed data path | Evidence / qualification |
| --- | --- | --- |
| protobuf-java-util | `JsonFormat.parseBytes` for JSON `bytes` fields | Confirmed in 4.33.0; 4.32.0 and reviewed 3.25.x use Guava. Do not mark all protobuf versions affected |
| SnakeYAML | `SafeConstructor.constructYamlBinary` / `!!binary` | Source; relevant only where untrusted YAML reaches this constructor |
| pac4j | `BasicAuthExtractor` | Campaign source review |
| Spring Framework | `Base64Utils` one-argument delegation in versions that contain it | Wrapper inventory; not a two-argument API finding |
| auth0 java-jwt | `JWTDecoder` URL decoding of token segments | 3.15.0 switches to JDK Base64; 3.14.0 used Commons Codec |
| fusionauth-jwt | `JWTDecoder` URL decoding | Source; do not assume every JWT library has the same codec |
| Micronaut / RESTEasy / Helidon / fastjson2 | Named Basic, h2c or binary-JSON call sites reported in the campaign | Source-review records only; pin the deployed release and inspect the enabled path before assigning exposure |
| JDK HTTP client | `NegotiateAuthentication` decoding a server challenge | Source; reverse direction: attacker-controlled server/proxy response, only when that authentication flow is used |

The presence of a library does not prove that an application parses the relevant
field, parses it before authentication, or allows external control of it.

## Negative paths and unresolved scope

The reviewed Commons Codec, Guava BaseEncoding, Jackson, Nimbus JOSE, jose4j,
jjwt, Netty and Undertow codec paths do not use the affected intrinsic. That is a
statement about those paths, not a guarantee for every plugin/application sharing
the process. Older Tomcat decoder implementations also differ from the switch
versions above.

Keycloak JWT preprocessing and Keycloak SAML are separate paths; a negative finding
on JWT must not be generalized to the whole product. Native-image deployments
and HotSpot deployments must likewise be separated.

Vert.x Basic handler findings conflict across the campaign's source-fetch passes:
some downloaded extracts were error pages. A JDK URL-decoder helper was identified,
but this pack does **not** promote the unresolved Basic path to confirmed status.
The proposed jmx_exporter inheritance path was also not established and is omitted
from the confirmed list.

Closed components such as Artifactory, ColdFusion, AEM Granite, ManageEngine and
YouTrack remain candidates requiring version-specific implementation review.
Fingerprints, `JSESSIONID` cookies and a bundled Java version are not call-path proof.

## Source entry points

These links let reviewers locate the underlying implementation; moving branches
can differ from the campaign snapshot:

- [Tomcat 9.0.89 BasicAuthenticator](https://github.com/apache/tomcat/blob/9.0.89/java/org/apache/catalina/authenticator/BasicAuthenticator.java)
- [Spring Security 6.1.0 BasicAuthenticationConverter](https://github.com/spring-projects/spring-security/blob/6.1.0/web/src/main/java/org/springframework/security/web/authentication/www/BasicAuthenticationConverter.java)
- [Elasticsearch 8.11.4 UsernamePasswordToken](https://github.com/elastic/elasticsearch/blob/v8.11.4/x-pack/plugin/core/src/main/java/org/elasticsearch/xpack/core/security/authc/support/UsernamePasswordToken.java)
- [auth0 java-jwt 3.15.0 JWTDecoder](https://github.com/auth0/java-jwt/blob/3.15.0/lib/src/main/java/com/auth0/jwt/JWTDecoder.java)
- [Protocol Buffers 4.33.0 JsonFormat](https://github.com/protocolbuffers/protobuf/blob/v33.0/java/util/src/main/java/com/google/protobuf/util/JsonFormat.java)
