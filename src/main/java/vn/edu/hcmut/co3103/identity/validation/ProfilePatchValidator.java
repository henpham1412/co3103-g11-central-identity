package vn.edu.hcmut.co3103.identity.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import vn.edu.hcmut.co3103.identity.dto.user.request.UpdateProfileRequest;

public class ProfilePatchValidator implements ConstraintValidator<ValidProfilePatch, UpdateProfileRequest> {
    @Override
    public boolean isValid(UpdateProfileRequest request, ConstraintValidatorContext context) {
        if (request == null) return true;
        if (request.hasField("full_name") && request.getFullName() == null) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Full name must not be null")
                    .addPropertyNode("fullName").addConstraintViolation();
            return false;
        }
        return request.hasUpdates();
    }
}
