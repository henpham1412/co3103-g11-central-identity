package vn.edu.hcmut.co3103.identity.security.jwt;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;
import vn.edu.hcmut.co3103.identity.exception.ApiErrorResponse;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.IdentityUserDetails;

import java.io.IOException;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            String token = authorization.substring(7).trim();
            UUID userId;
            try {
                // Extraction verifies the signature and the complete, canonical identity contract.
                userId = UUID.fromString(jwtService.extractUserId(token));
            } catch (JwtException | IllegalArgumentException exception) {
                // Only token parsing failures are treated as invalid credentials.
                filterChain.doFilter(request, response);
                return;
            }
            try {
                var user = userRepository.findById(userId).orElse(null);
                if (user != null) {
                    var userDetails = new IdentityUserDetails(user);
                    if (jwtService.isTokenValid(token, userDetails)
                            && userDetails.isEnabled() && userDetails.isAccountNonLocked()
                            && userDetails.isAccountNonExpired() && userDetails.isCredentialsNonExpired()) {
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(
                                        userDetails, null, userDetails.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        var context = SecurityContextHolder.createEmptyContext();
                        context.setAuthentication(authentication);
                        SecurityContextHolder.setContext(context);
                    }
                }
            } catch (RuntimeException exception) {
                // Infrastructure failures (including transaction creation) are server errors, not bad tokens.
                log.error("User lookup failed for request {}", request.getRequestURI(), exception);
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                objectMapper.writeValue(response.getOutputStream(), ApiErrorResponse.builder()
                        .code("INTERNAL_SERVER_ERROR")
                        .message("An unexpected internal error occurred").build());
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
