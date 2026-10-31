package vn.edu.hcmut.co3103.identity.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(DuplicateEmailException.class)
    public ResponseEntity<ApiErrorResponse> handleDuplicateEmail(
            DuplicateEmailException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.CONFLICT, exception.getMessage(), request)
                        .code("EMAIL_ALREADY_REGISTERED").build());
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiErrorResponse> handleDataIntegrityViolation(
            DataIntegrityViolationException exception, HttpServletRequest request) {
        if (DataIntegrityViolationClassifier.isEmailUniqueViolation(exception)) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(errorResponse(HttpStatus.CONFLICT,
                            "Data conflicts with an existing record", request)
                            .code("EMAIL_ALREADY_REGISTERED").build());
        }
        if (!DataIntegrityViolationClassifier.isRequestDataViolation(exception)) {
            return handleUnexpectedException(exception, request);
        }
        HttpStatus status = HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(status, "Request violates a data constraint", request).build());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccessDenied(
            AccessDeniedException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.FORBIDDEN, "Access is denied", request).build());
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidCredentials(
            InvalidCredentialsException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.UNAUTHORIZED, exception.getMessage(), request)
                        .code("INVALID_CREDENTIALS").build());
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccountLocked(
            AccountLockedException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.LOCKED)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.LOCKED, exception.getMessage(), request)
                        .code("LOGIN_TEMPORARILY_LOCKED")
                        .lockedUntil(exception.getLockedUntil())
                        .build());
    }

    @ExceptionHandler(AccountInactiveException.class)
    public ResponseEntity<ApiErrorResponse> handleAccountInactive(
            AccountInactiveException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.FORBIDDEN, exception.getMessage(), request)
                        .code("ACCOUNT_NOT_ACTIVE").build());
    }

    @ExceptionHandler(InvalidClientException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidClient(
            InvalidClientException exception, HttpServletRequest request) {
        return ResponseEntity.badRequest().contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.BAD_REQUEST, exception.getMessage(), request)
                        .code("INVALID_CLIENT").build());
    }

    @ExceptionHandler(InvalidRedirectUriException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidRedirectUri(
            InvalidRedirectUriException exception, HttpServletRequest request) {
        return ResponseEntity.badRequest().contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.BAD_REQUEST, exception.getMessage(), request)
                        .code("INVALID_REDIRECT_URI").build());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidation(
            MethodArgumentNotValidException exception, HttpServletRequest request) {
        Map<String, String> validationErrors = new LinkedHashMap<>();
        exception.getBindingResult().getFieldErrors().forEach(error ->
                validationErrors.putIfAbsent(error.getField(), error.getDefaultMessage()));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.BAD_REQUEST, "Validation failed", request)
                        .code("VALIDATION_ERROR")
                        .validationErrors(validationErrors)
                        .build());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiErrorResponse> handleHttpMessageNotReadable(
            HttpMessageNotReadableException exception, HttpServletRequest request) {
        // Parser messages can contain raw request tokens, including passwords.
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.BAD_REQUEST,
                        "Required request body is missing or malformed", request).build());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiErrorResponse> handleIllegalArgument(
            IllegalArgumentException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.BAD_REQUEST, "Invalid request argument", request).build());
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiErrorResponse> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException exception, HttpServletRequest request) {
        var response = ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .contentType(MediaType.APPLICATION_JSON);
        if (exception.getSupportedHttpMethods() != null) {
            response.allow(exception.getSupportedHttpMethods().toArray(org.springframework.http.HttpMethod[]::new));
        }
        return response.body(errorResponse(HttpStatus.METHOD_NOT_ALLOWED,
                "Request method is not supported", request).build());
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ApiErrorResponse> handleMediaTypeNotSupported(
            HttpMediaTypeNotSupportedException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                        "Request media type is not supported", request).build());
    }

    @ExceptionHandler(HttpMediaTypeNotAcceptableException.class)
    public ResponseEntity<ApiErrorResponse> handleMediaTypeNotAcceptable(
            HttpMediaTypeNotAcceptableException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.NOT_ACCEPTABLE,
                        "Requested response media type is not supported", request).code("NOT_ACCEPTABLE").build());
    }

    @ExceptionHandler({NoResourceFoundException.class, ResourceNotFoundException.class})
    public ResponseEntity<ApiErrorResponse> handleNoResourceFound(
            Exception exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.NOT_FOUND, "Requested resource was not found", request)
                        .code("RESOURCE_NOT_FOUND").build());
    }

    @ExceptionHandler(ErrorResponseException.class)
    public ResponseEntity<ApiErrorResponse> handleHttpError(
            ErrorResponseException exception, HttpServletRequest request) {
        HttpStatus status = HttpStatus.resolve(exception.getStatusCode().value());
        if (status == null || !status.isError()) {
            return handleUnexpectedException(exception, request);
        }
        // Framework reasons and ProblemDetail properties may contain internal details.
        return ResponseEntity.status(status).headers(exception.getHeaders())
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(status, status.getReasonPhrase(), request).build());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleUnexpectedException(
            Exception exception, HttpServletRequest request) {
        log.error("Unhandled exception for request {}", request.getRequestURI(), exception);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorResponse(HttpStatus.INTERNAL_SERVER_ERROR,
                        "An unexpected internal error occurred", request).build());
    }

    private ApiErrorResponse.ApiErrorResponseBuilder errorResponse(
            HttpStatus status, String message, HttpServletRequest request) {
        log.debug("Request {} failed with status {}: {}", request.getRequestURI(), status.value(), message);
        return ApiErrorResponse.builder()
                .status(status.value())
                .error(status.getReasonPhrase())
                .code(switch (status) {
                    case BAD_REQUEST -> "INVALID_REQUEST";
                    case UNAUTHORIZED -> "UNAUTHORIZED";
                    case FORBIDDEN -> "ACCESS_DENIED";
                    case NOT_FOUND -> "RESOURCE_NOT_FOUND";
                    default -> status.name();
                })
                .message(message)
                .path(request.getRequestURI());
    }
}
