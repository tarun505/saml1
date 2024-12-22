package com.saml1.saml1;

import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Files;

@RestController
public class MetadataController {

    @GetMapping("/saml2/service-provider-metadata/okta")
    public ResponseEntity<String> getMetadata() throws IOException {
        // Load metadata XML file from the classpath or filesystem
        ClassPathResource metadataResource = new ClassPathResource("sp-metadata.xml");
        String metadata = new String(Files.readAllBytes(metadataResource.getFile().toPath()));

        // Return the metadata XML content with the proper content type
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_XML)
                .body(metadata);
    }
}


