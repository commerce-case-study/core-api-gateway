package com.metranet.finbox.core.filter;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractNameValueGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.metranet.finbox.core.exception.AuthException;
import com.metranet.finbox.service.member.api.ClientService;
import com.metranet.finbox.service.member.dto.ClientDto;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class BasicFilter extends AbstractNameValueGatewayFilterFactory {

    @Autowired
    ClientService clientService;
    
    Logger logger = LoggerFactory.getLogger(BasicFilter.class);
    
    /**
     * Decode Basic Authorization
     * @param basicheader
     * @return
     */
    private String decodeToken(String basicheader) {
        return new String(Base64.getDecoder().decode(basicheader), 
                StandardCharsets.UTF_8);
    }
    
    /**
     * Authorize by Client Id
     * @param decodedToken
     * @return
     */
    private boolean isAuthorized(String decodedToken) {
        if(StringUtils.isBlank(decodedToken)){
            return false;
        }
        
        String[] credentials = decodedToken.split(":", 2);
        String clientid = credentials[0];
        String clientsc = credentials[1];
        
        ClientDto client = clientService.findByClientId(clientid);
        if(null == client) {
            return false;
        }
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        if(encoder.matches(clientsc, client.getClientSecret())) {
            return true;
        }
        
        return false;
    }
    
    @Override
    public GatewayFilter apply(NameValueConfig config) {
        return (exchange, chain) -> {
            // Do Nothing, Pass through request
            if(!"true".equals(config.getValue())) {
                return chain.filter(exchange);
            }
            // Verify Basic Token
            try {
                String token = decodeToken(extractBasicAuth(exchange.getRequest()));
                if(isAuthorized(token)) {
                    /*
                     * Remove Header with key Authorization, 
                     * it should not relay to the service, 
                     * it's existence can trigger Authorization event. 
                     */
                    Consumer<HttpHeaders> header = head -> head.remove("Authorization");
                    ServerHttpRequest request = exchange.getRequest().mutate().headers(header).build();
                    
                    // Return The Request after enrich 
                    return chain.filter(exchange.mutate().request(request).build());
                }
                return this.onError(exchange, "Unauthorize Access");
            } catch (Exception ex) {
                ex.printStackTrace();
                return this.onError(exchange, "Error Unauthorize");
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
    
    private String extractBasicAuth(ServerHttpRequest request) {
        List<String> headers = request.getHeaders().get("Authorization");
        if (null == headers || headers.isEmpty()) {
            throw new AuthException("Unauthorized Access");
        }

        String[] components = StringUtils.trimToEmpty(headers.get(0)).split("\\s");
        if (components.length != 2) {
            throw new AuthException("Authorization format is invalid");
        }
        if (!components[0].equals("Basic")) {
            throw new AuthException("Authorization Basic is invalid");
        }

        return components[1].trim();
    }

}
