package vn.edu.hcmut.co3103.identity.config;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ErrorReportValve;
import org.apache.coyote.ActionCode;
import org.springframework.http.MediaType;
import tools.jackson.databind.json.JsonMapper;
import vn.edu.hcmut.co3103.identity.exception.ApiErrorResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

/** Covers URI/parser rejections before a servlet context (and Spring) can be selected. */
public class JsonErrorReportValve extends ErrorReportValve {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    @Override
    protected void report(Request request, Response response, Throwable throwable) {
        if (response.getStatus() < 400 || response.getContentWritten() > 0 || !response.setErrorReported()) {
            return;
        }
        AtomicBoolean ioAllowed = new AtomicBoolean(false);
        response.getCoyoteResponse().action(ActionCode.IS_IO_ALLOWED, ioAllowed);
        if (!ioAllowed.get()) {
            return;
        }
        // Never echo the URI, parser message, or throwable: each may contain untrusted data.
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        try {
            var writer = response.getReporter();
            if (writer != null) {
                writer.write(MAPPER.writeValueAsString(ApiErrorResponse.forStatus(response.getStatus())));
                response.finishResponse();
            }
        } catch (IOException ignored) {
            // The peer disconnected; no further error page can be delivered.
        }
    }
}
