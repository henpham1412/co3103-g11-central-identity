package vn.edu.hcmut.co3103.identity.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/** Reject unacceptable JSON before argument binding or controller/service side effects. */
public class JsonAcceptInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws HttpMediaTypeNotAcceptableException {
        // Enforce the contract of endpoints that explicitly produce only application/json.
        // Leave static resources and endpoints offering other representations to MVC.
        if (!Set.of(MediaType.APPLICATION_JSON).equals(
                request.getAttribute(HandlerMapping.PRODUCIBLE_MEDIA_TYPES_ATTRIBUTE))) {
            return true;
        }

        List<MediaType> accepted;
        try {
            accepted = MediaType.parseMediaTypes(Collections.list(request.getHeaders(HttpHeaders.ACCEPT)));
        } catch (IllegalArgumentException exception) {
            throw new HttpMediaTypeNotAcceptableException(List.of(MediaType.APPLICATION_JSON));
        }
        if (accepted.isEmpty()) {
            return true;
        }

        int bestType = -1;
        int bestParameters = -1;
        double quality = 0;
        for (MediaType range : accepted) {
            if (!range.includes(MediaType.APPLICATION_JSON) || !parametersMatchJson(range)) {
                continue;
            }
            int type = range.isWildcardType() ? 0 : range.isWildcardSubtype() ? 1 : 2;
            int parameters = (int) range.getParameters().keySet().stream()
                    .filter(name -> !"q".equalsIgnoreCase(name)).count();
            // RFC 9110 section 12.5.1: specificity determines effective quality, not header order
            // or the largest q. In particular, an explicit q=0 overrides a positive wildcard.
            if (type > bestType || (type == bestType && parameters > bestParameters)) {
                bestType = type;
                bestParameters = parameters;
                quality = range.getQualityValue();
            } else if (type == bestType && parameters == bestParameters) {
                quality = Math.max(quality, range.getQualityValue());
            }
        }
        if (quality <= 0) {
            throw new HttpMediaTypeNotAcceptableException(List.of(MediaType.APPLICATION_JSON));
        }
        return true;
    }

    private boolean parametersMatchJson(MediaType range) {
        return range.getParameters().entrySet().stream().allMatch(parameter ->
                "q".equalsIgnoreCase(parameter.getKey())
                        || ("charset".equalsIgnoreCase(parameter.getKey())
                        && "UTF-8".equalsIgnoreCase(parameter.getValue().replace("\"", ""))));
    }
}
