package gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.setResponseStatus;

@Component
public class GatewayTokenFilter extends AbstractGatewayFilterFactory<GatewayTokenFilter.Config> {

    @Autowired
    private JwtConfig jwtConfig;

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            try {    // exceptions might be thrown in creating the claims if for example the token is expired
                String header = exchange.getRequest().getHeaders().get(jwtConfig.getHeader()).get(0);

                if (header == null || !header.startsWith(jwtConfig.getPrefix())) {
                    setResponseStatus(exchange, HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }
                String token = header.replace(jwtConfig.getPrefix(), "");

                Claims claims = Jwts.parser()
                        .setSigningKey(jwtConfig.getSecret().getBytes())
                        .parseClaimsJws(token)
                        .getBody();

                String username = claims.getSubject();
                if (username == null) {
                    setResponseStatus(exchange, HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }

                String uid = claims.get("userId", String.class);

                ServerHttpRequest request = exchange.getRequest().mutate().
                        header("uid", uid).build();

                return chain.filter(exchange.mutate().request(request).build());

            } catch (Exception e) {
                setResponseStatus(exchange, HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        };
    }

    @Bean
    public JwtConfig jwtConfig() { return new JwtConfig(); }

    @Override
    public Config newConfig() {
        return new Config();
    }

    public static class Config{
        //fields
    }
}
