package vn.edu.hcmut.co3103.identity.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;
import java.util.Collections;

/** Only explicitly trusted socket peers may supply X-Forwarded-For. Never resolves DNS. */
@Component
public class ClientIpResolver {
    private final List<IpAddressMatcher> trustedProxies;

    public ClientIpResolver(@Value("${app.recovery.trusted-proxies:}") String trustedProxies) {
        this.trustedProxies = Arrays.stream(trustedProxies.split(",")).map(String::trim)
                .filter(value -> !value.isEmpty()).map(value -> {
                    InetAddress.ofLiteral(value.split("/", 2)[0]);
                    return new IpAddressMatcher(value);
                }).toList();
    }

    public InetAddress resolve(HttpServletRequest request) {
        InetAddress peer = InetAddress.ofLiteral(request.getRemoteAddr());
        if (!trusted(peer)) return peer;
        String forwarded = String.join(",", Collections.list(request.getHeaders("X-Forwarded-For")));
        if (forwarded.isEmpty() || forwarded.length() > 2048) return peer;
        String[] hops = forwarded.split(",", -1);
        if (hops.length > 32) return peer;
        try {
            InetAddress client = peer;
            for (int i = hops.length - 1; i >= 0 && trusted(client); i--) {
                String literal = hops[i].trim();
                // Exclude hostnames, ports, scoped IPv6, and ambiguous shortened IPv4 notation.
                if (!literal.matches("[0-9a-fA-F:.]+")
                        || (!literal.contains(":") && literal.split("\\.", -1).length != 4)) return peer;
                client = InetAddress.ofLiteral(literal);
            }
            return client;
        } catch (IllegalArgumentException exception) {
            return peer;
        }
    }

    private boolean trusted(InetAddress address) {
        return trustedProxies.stream().anyMatch(proxy -> proxy.matches(address.getHostAddress()));
    }
}
