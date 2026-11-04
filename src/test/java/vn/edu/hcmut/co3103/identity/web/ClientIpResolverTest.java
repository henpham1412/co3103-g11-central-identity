package vn.edu.hcmut.co3103.identity.web;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import java.net.InetAddress;
import static org.assertj.core.api.Assertions.*;

class ClientIpResolverTest {
    @ParameterizedTest
    @CsvSource({
            "198.51.100.4, 1.1.1.1, 198.51.100.4",
            "10.0.0.1, 198.51.100.4, 198.51.100.4",
            "2001:db8::4, 1.1.1.1, 2001:db8::4",
            "10.0.0.1, 2001:db8::4, 2001:db8::4",
            "10.0.0.1, forged.example, 10.0.0.1",
            "10.0.0.1, 127.1, 10.0.0.1",
            "10.0.0.1, 192.0.2.1:1234, 10.0.0.1"
    })
    void onlyExplicitlyTrustedPeersSupplyLiteralForwardedAddresses(String peer, String header, String expected) {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr(peer);
        request.addHeader("X-Forwarded-For", header);
        assertThat(new ClientIpResolver("10.0.0.0/8").resolve(request)).isEqualTo(InetAddress.ofLiteral(expected));
    }

    @Test
    void walksChainFromRightAndStopsAtFirstUntrustedHop() {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("X-Forwarded-For", "1.1.1.1, 198.51.100.9, 10.0.0.2");
        assertThat(new ClientIpResolver("10.0.0.0/8").resolve(request).getHostAddress()).isEqualTo("198.51.100.9");
        assertThat(new ClientIpResolver("").resolve(request).getHostAddress()).isEqualTo("10.0.0.1");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", ",", "garbage", "1.1.1.1, ", "[2001:db8::1]:80"})
    void malformedHeadersFallBackToPeer(String header) {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("X-Forwarded-For", header);
        assertThat(new ClientIpResolver("10.0.0.1").resolve(request).getHostAddress()).isEqualTo("10.0.0.1");
    }

    @Test
    void rejectsHostnamesInTrustedProxyConfiguration() {
        assertThatThrownBy(() -> new ClientIpResolver("localhost")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void repeatedHeadersCannotHideTheRightmostUntrustedHop() {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("X-Forwarded-For", "1.1.1.1");
        request.addHeader("X-Forwarded-For", "198.51.100.9");
        assertThat(new ClientIpResolver("10.0.0.0/8").resolve(request).getHostAddress()).isEqualTo("198.51.100.9");
    }
}
