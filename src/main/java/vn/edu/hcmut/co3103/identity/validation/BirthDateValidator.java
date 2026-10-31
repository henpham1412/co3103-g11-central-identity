package vn.edu.hcmut.co3103.identity.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.time.LocalDate;

public class BirthDateValidator implements ConstraintValidator<BirthDate, LocalDate> {
    private static final LocalDate MINIMUM = LocalDate.of(1900, 1, 1);

    @Override
    public boolean isValid(LocalDate value, ConstraintValidatorContext context) {
        return value == null || (!value.isBefore(MINIMUM)
                && !value.isAfter(LocalDate.now(context.getClockProvider().getClock())));
    }
}
