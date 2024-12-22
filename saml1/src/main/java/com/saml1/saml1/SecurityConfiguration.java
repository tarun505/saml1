package com.saml1.saml1;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.web.SecurityFilterChain;

import java.security.cert.CertificateFactory;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain samlSecurityFilterChain(HttpSecurity http, RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/home").permitAll()
                .anyRequest().authenticated()
            )
            .saml2Login(saml2 -> saml2
                .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository)
                .defaultSuccessUrl("/secured", true)
            )
            .logout(logout -> logout
                    .logoutSuccessUrl("/home") // Redirect after successful logout
                    .permitAll() // Allow public access to the logout
                );
            
        return http.build();
    }
   
    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        RelyingPartyRegistration registration = RelyingPartyRegistration
                .withRegistrationId("okta")
                .assertingPartyDetails(party -> party
                    .entityId("http://www.okta.com/exklwr8jumcgfwr5V5d7")
                    .singleSignOnServiceLocation("https://dev-92982234.okta.com/app/dev-92982234_samlexample_1/exklwr8jumcgfwr5V5d7/sso/saml")
                    .verificationX509Credentials(credentials -> credentials
                        .add(createVerificationCredential("certs/idp-public-cert.pem"))
                    )
                )
                .entityId("http://localhost:8080/saml2/service-provider-metadata/okta")
                .signingX509Credentials(credentials -> credentials
                    .add(createSigningCredential("certs/sp-private-key.pem", "certs/sp-public-cert.pem"))
                )
                .assertionConsumerServiceLocation("http://localhost:8080/login/saml2/sso/okta")
                .build();

        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    private Saml2X509Credential createVerificationCredential(String certificatePath) {
        try (InputStream certStream = getClass().getClassLoader().getResourceAsStream(certificatePath)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certStream);
            return Saml2X509Credential.verification(certificate);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load verification certificate", e);
        }
    }

    private Saml2X509Credential createSigningCredential(String privateKeyPath, String publicCertPath) {
        try {
            InputStream keyStream = getClass().getClassLoader().getResourceAsStream(privateKeyPath);
            InputStream certStream = getClass().getClassLoader().getResourceAsStream(publicCertPath);

            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(certStream);

            String privateKeyPem = new String(keyStream.readAllBytes());
            String privateKeyContent = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

            byte[] decodedKey = java.util.Base64.getDecoder().decode(privateKeyContent);
            java.security.PrivateKey privateKey = java.security.KeyFactory.getInstance("RSA")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(decodedKey));

            return Saml2X509Credential.signing(privateKey, certificate);  
        } catch (Exception e) {
            throw new RuntimeException("Failed to load signing credential", e);
        }
    }
}
