package vn.edu.hcmut.co3103.identity.controller;

import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.edu.hcmut.co3103.identity.dto.user.response.CurrentUserResponse;
import vn.edu.hcmut.co3103.identity.security.IdentityUserDetails;

@RestController
@RequestMapping({"/users", "/api/v1/users"})
public class CurrentUserController {

    @GetMapping(value = "/me", produces = MediaType.APPLICATION_JSON_VALUE)
    public CurrentUserResponse currentUser(@AuthenticationPrincipal IdentityUserDetails user) {
        // The filter reloads the database identity on each request. LMS roles are managed by each LMS.
        return new CurrentUserResponse(user.getUserId(), user.getUsername(), user.getFullName(),
                user.getStatus(), "USER");
    }
}
