package vn.edu.hcmut.co3103.identity.validation;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.ValueDeserializer;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;

/** Preserve explicit nulls; accept only an exact ISO calendar-date string for supplied values. */
public class StrictBirthDateDeserializer extends ValueDeserializer<LocalDate> {
    @Override
    public LocalDate deserialize(JsonParser parser, DeserializationContext context) {
        if (parser.hasToken(JsonToken.VALUE_STRING)) {
            String value = parser.getString();
            if (value.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}")) {
                try {
                    // ISO_LOCAL_DATE uses strict resolution, including leap-year checks.
                    return LocalDate.parse(value);
                } catch (DateTimeParseException ignored) {
                    // Report the same sanitized shape error for impossible calendar dates.
                }
            }
        }
        return context.reportInputMismatch(LocalDate.class, "Date of birth must be a YYYY-MM-DD string or null");
    }
}
