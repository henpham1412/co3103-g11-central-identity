package vn.edu.hcmut.co3103.identity.exception;

import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DuplicateKeyException;

import java.sql.SQLException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/** Identifies unique violations without mistaking SQL values or column names for constraints. */
public final class DataIntegrityViolationClassifier {

    private static final String EMAIL_CONSTRAINT = "users_email_key";
    private static final Pattern EMAIL_CONSTRAINT_MESSAGE = Pattern.compile(
            "(?:constraint|violates)\\s+[\"']?users_email_key\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern EMAIL_KEY_MESSAGE = Pattern.compile(
            "\\bKey\\s*\\(\\s*email\\s*\\)\\s*=", Pattern.CASE_INSENSITIVE);
    private static final Pattern UNIQUE_MESSAGE = Pattern.compile(
            "\\bduplicate key\\b|\\bunique constraint\\b", Pattern.CASE_INSENSITIVE);

    private DataIntegrityViolationClassifier() {
    }

    public static boolean isEmailUniqueViolation(Throwable exception) {
        if (!isUniqueViolation(exception)) {
            return false;
        }
        List<Throwable> causes = causes(exception);
        for (Throwable cause : causes) {
            if (cause instanceof ConstraintViolationException violation && violation.getConstraintName() != null) {
                return EMAIL_CONSTRAINT.equalsIgnoreCase(violation.getConstraintName());
            }
        }
        return causes.stream().anyMatch(cause -> cause.getMessage() != null
                && (EMAIL_CONSTRAINT_MESSAGE.matcher(cause.getMessage()).find()
                || EMAIL_KEY_MESSAGE.matcher(cause.getMessage()).find()));
    }

    public static boolean isUniqueViolation(Throwable exception) {
        List<Throwable> causes = causes(exception);
        // Structured driver metadata takes precedence over text that can include user data.
        for (Throwable cause : causes) {
            if (cause instanceof SQLException sql && sql.getSQLState() != null) {
                return "23505".equals(sql.getSQLState());
            }
        }
        return causes.stream().anyMatch(cause -> cause instanceof DuplicateKeyException
                || cause instanceof ConstraintViolationException violation
                && (violation.getKind() == ConstraintViolationException.ConstraintKind.UNIQUE
                || EMAIL_CONSTRAINT.equalsIgnoreCase(violation.getConstraintName()))
                || cause.getMessage() != null && UNIQUE_MESSAGE.matcher(cause.getMessage()).find());
    }

    /** Known invalid input is a 400; unidentified or unexpected uniqueness failures remain server errors. */
    public static boolean isRequestDataViolation(Throwable exception) {
        for (Throwable cause : causes(exception)) {
            if (cause instanceof SQLException sql && sql.getSQLState() != null) {
                String state = sql.getSQLState();
                return state.startsWith("22") || Set.of("23502", "23503", "23514").contains(state);
            }
        }
        return false;
    }

    private static List<Throwable> causes(Throwable exception) {
        List<Throwable> causes = new ArrayList<>();
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        ArrayDeque<Throwable> pending = new ArrayDeque<>();
        pending.add(exception);
        while (!pending.isEmpty()) {
            Throwable cause = pending.removeFirst();
            if (!seen.add(cause)) {
                continue;
            }
            causes.add(cause);
            if (cause.getCause() != null) {
                pending.add(cause.getCause());
            }
            if (cause instanceof SQLException sql && sql.getNextException() != null) {
                pending.add(sql.getNextException());
            }
        }
        return causes;
    }
}
