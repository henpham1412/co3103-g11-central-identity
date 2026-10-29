package vn.edu.hcmut.co3103.identity.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(DuplicateEmailException.class)
    public ResponseEntity<ApiErrorResponse> handleDuplicateEmail(
            DuplicateEmailException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(errorResponse(HttpStatus.CONFLICT, exception.getMessage(), request).build());
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiErrorResponse> handleDataIntegrityViolation(
            DataIntegrityViolationException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(errorResponse(HttpStatus.CONFLICT,
                        "Data conflicts with an existing record", request).build());
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidCredentials(
            InvalidCredentialsException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(errorResponse(HttpStatus.UNAUTHORIZED, exception.getMessage(), request).build());
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccountLocked(
            AccountLockedException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.LOCKED)
                .body(errorResponse(HttpStatus.LOCKED, exception.getMessage(), request)
                        .lockedUntil(exception.getLockedUntil())
                        .build());
    }

    @ExceptionHandler(AccountInactiveException.class)
    public ResponseEntity<ApiErrorResponse> handleAccountInactive(
            AccountInactiveException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(errorResponse(HttpStatus.FORBIDDEN, exception.getMessage(), request).build());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidation(
            MethodArgumentNotValidException exception, HttpServletRequest request) {
        Map<String, String> validationErrors = new LinkedHashMap<>();
        exception.getBindingResult().getFieldErrors().forEach(error ->
                validationErrors.putIfAbsent(error.getField(), error.getDefaultMessage()));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(errorResponse(HttpStatus.BAD_REQUEST, "Validation failed", request)
                        .validationErrors(validationErrors)
                        .build());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiErrorResponse> handleHttpMessageNotReadable(
            HttpMessageNotReadableException exception, HttpServletRequest request) {
        // Parser messages can contain raw request tokens, including passwords.
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(errorResponse(HttpStatus.BAD_REQUEST,
                        "Required request body is missing or malformed", request).build());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiErrorResponse> handleIllegalArgument(
            IllegalArgumentException exception, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(errorResponse(HttpStatus.BAD_REQUEST, "Invalid request argument", request).build());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleUnexpectedException(
            Exception exception, HttpServletRequest request) {
        log.error("Unhandled exception for request {}", request.getRequestURI(), exception);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse(HttpStatus.INTERNAL_SERVER_ERROR,
                        "An unexpected internal error occurred", request).build());
    }

    private ApiErrorResponse.ApiErrorResponseBuilder errorResponse(
            HttpStatus status, String message, HttpServletRequest request) {
        log.debug("Request {} failed with status {}: {}", request.getRequestURI(), status.value(), message);
        return ApiErrorResponse.builder()
                .status(status.value())
                .error(status.getReasonPhrase())
                .message(message)
                .path(request.getRequestURI());
    }
}
