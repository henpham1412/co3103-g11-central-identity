package vn.edu.hcmut.co3103.identity.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import vn.edu.hcmut.co3103.identity.config.SecurityConfig;
import vn.edu.hcmut.co3103.identity.repository.UserRepository;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtAuthenticationFilter;
import vn.edu.hcmut.co3103.identity.security.jwt.JwtService;

import static org.hamcrest.Matchers.aMapWithSize;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(JwksController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, JwtService.class})
class JwksControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private UserRepository userRepository;

    @Test
    void exposesOnlyPublicRsaKeyWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json").header(HttpHeaders.ORIGIN, "http://localhost:5173"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:5173"))
                .andExpect(jsonPath("$", aMapWithSize(1)))
                .andExpect(jsonPath("$.keys.length()").value(1))
                .andExpect(jsonPath("$.keys[0]", aMapWithSize(6)))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].kid").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].e").value("AQAB"));
        verifyNoInteractions(userRepository);
    }

    @Test
    void invalidTokenDoesNotPreventPublicKeyDiscovery() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json").header(HttpHeaders.AUTHORIZATION, "Bearer invalid"))
                .andExpect(status().isOk());
        verifyNoInteractions(userRepository);
    }

    @Test
    void publicAccessIsLimitedToGet() throws Exception {
        mockMvc.perform(post("/.well-known/jwks.json")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/.well-known/other.json")).andExpect(status().isUnauthorized());
    }
}
