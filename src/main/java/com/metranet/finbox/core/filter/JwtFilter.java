package com.metranet.finbox.core.filter;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractNameValueGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.metranet.finbox.core.exception.AuthException;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class JwtFilter extends AbstractNameValueGatewayFilterFactory {

    Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    
    private static final String X_JWT_SUB_HEADER = "X-jwt-sub";

    @Value("${finbox.keystore.alias}")
    private String keystoreAlias;
    
    @Value("${finbox.auth.server}")
    private String authServer;
    
    @Value("${finbox.keystore.id}")
    private String keystoreId;
    
    @Bean
    public JWTVerifier customJwtVerifier() throws JwkException, IOException {
        UrlJwkProvider urlJwkProvider = new UrlJwkProvider(new URL(authServer + "/oauth/.well-known/jwks.json"));
        Jwk jwk = urlJwkProvider.get(keystoreId);
        return JWT.require(Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null))
                .withIssuer(keystoreAlias)
                .build();
    }
    
    @Override
    public GatewayFilter apply(NameValueConfig config) {
        return (exchange, chain) -> {
            // Do Nothing, Pass through request
            if(!"true".equals(config.getValue())) {
                return chain.filter(exchange);
            }
            // Verify JWT Token
            try {
                String token = this.extractJwtToken(exchange.getRequest());
                DecodedJWT decodedJWT = customJwtVerifier().verify(token);
                
                ServerHttpRequest request = exchange.getRequest().mutate().
                        header(X_JWT_SUB_HEADER, decodedJWT.getPayload()).
                        build();

                return chain.filter(exchange.mutate().request(request).build());

            } catch (Exception ex) {
                ex.printStackTrace();
                return this.onError(exchange, ex.getMessage());
            }
        };
    }
    
    private Mono<Void> onError(ServerWebExchange exchange, String err) {
        ServerHttpResponse response = exchange.getResponse();
        
        // Prepare Body
        String body  = "{\"error_message\":\"" + err + "\"}";
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        
        // Prepare HTTP Status
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.writeWith(Flux.just(buffer));
    }

    private String extractJwtToken(ServerHttpRequest request) {
        List<String> headers = request.getHeaders().get("Authorization");
        if (null == headers || headers.isEmpty()) {
            throw new AuthException("Unauthorized Access");
        }

        String[] components = StringUtils.trimToEmpty(headers.get(0)).split("\\s");
        if (components.length != 2) {
            throw new AuthException("Authorization format is invalid");
        }
        if (!components[0].equals("Bearer")) {
            throw new AuthException("Authorization Bearer is invalid");
        }

        return components[1].trim();
    }
}
