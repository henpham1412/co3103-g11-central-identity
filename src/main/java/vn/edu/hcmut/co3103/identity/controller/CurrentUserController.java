package vn.edu.hcmut.co3103.identity.controller;

import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.edu.hcmut.co3103.identity.dto.user.request.UpdateProfileRequest;
import vn.edu.hcmut.co3103.identity.dto.user.response.CurrentUserProfileResponse;
import vn.edu.hcmut.co3103.identity.dto.user.response.UpdateProfileResponse;
import vn.edu.hcmut.co3103.identity.security.IdentityUserDetails;
import vn.edu.hcmut.co3103.identity.service.UserService;

@RestController
@RequestMapping({"/users", "/api/v1/users"})
public class CurrentUserController {

    private final UserService userService;

    public CurrentUserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping(value = {"/me", "/me/profile"}, produces = MediaType.APPLICATION_JSON_VALUE)
    public CurrentUserProfileResponse currentUserProfile(@AuthenticationPrincipal IdentityUserDetails user) {
        return userService.getCurrentUserProfile(user.getUserId());
    }

    @PatchMapping(value = "/me", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public UpdateProfileResponse updateProfile(
            @AuthenticationPrincipal IdentityUserDetails user,
            @Valid @RequestBody UpdateProfileRequest request) {
        return userService.updateProfile(user.getUserId(), request);
    }
}
