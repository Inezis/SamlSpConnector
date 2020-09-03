package sk.inezis.saml_sp_connector.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import sk.inezis.saml_sp_connector.api.SamlApi;
import sk.inezis.saml_sp_connector.dto.ErrorCode;
import sk.inezis.saml_sp_connector.dto.SamlRequestGenerationResponse;
import sk.inezis.saml_sp_connector.dto.SamlResponseParsingRequest;
import sk.inezis.saml_sp_connector.dto.SamlResponseParsingResponse;
import sk.inezis.saml_sp_connector.exception.SamlValidationException;
import sk.inezis.saml_sp_connector.service.SamlService;

import javax.validation.Valid;
import java.util.Map;

@Controller
public class SamlController implements SamlApi {
    private static final Logger logger = LoggerFactory.getLogger(SamlController.class);

    private final SamlService samlService;

    public SamlController(SamlService samlService) {
        this.samlService = samlService;
    }

    @Override
    public ResponseEntity<SamlRequestGenerationResponse> generateSamlRequest() {
        SamlRequestGenerationResponse response;
        try {
            byte[] samlRequest = samlService.generateSamlRequest();
            response = new SamlRequestGenerationResponse().base64SamlRequestData(samlRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error(e.getLocalizedMessage(), e);

            response = new SamlRequestGenerationResponse().errorCode(ErrorCode.UNKNOWN)
                    .errorMessage(e.getLocalizedMessage())
                    .base64SamlRequestData(null);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(response);
        }
    }

    @Override
    public ResponseEntity<SamlResponseParsingResponse> parseSamlResponse(@Valid SamlResponseParsingRequest samlResponseParsingRequest) {
        SamlResponseParsingResponse response;
        try {
            Map<String, String> samlAttributes = samlService.parseSamlResponse(samlResponseParsingRequest.getBase64SamlResponseData());
            response = new SamlResponseParsingResponse().samlAttributes(samlAttributes);
            return ResponseEntity.ok(response);
        } catch (SamlValidationException e) {
            logger.error(e.getLocalizedMessage(), e);

            response = new SamlResponseParsingResponse().errorCode(ErrorCode.UNKNOWN)
                    .errorMessage(e.getLocalizedMessage())
                    .samlAttributes(null);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(response);
        }
    }
}
