package vn.edu.hcmut.co3103.identity.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.edu.hcmut.co3103.identity.exception.ApiErrorResponse;

/** Replaces Boot's default map/HTML response for servlet error dispatches. */
@RestController
public class ApiErrorController implements ErrorController {

    @RequestMapping("${server.error.path:/error}")
    ResponseEntity<ApiErrorResponse> error(HttpServletRequest request) {
        Object value = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        HttpStatus status = value instanceof Integer code ? HttpStatus.resolve(code) : null;
        if (status == null || !status.isError()) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON)
                .body(ApiErrorResponse.forStatus(status.value()));
    }
}
