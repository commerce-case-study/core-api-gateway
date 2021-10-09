package com.commerce.core.gateway.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.commerce.core.gateway.dto.ClientDto;

@FeignClient(name = ClientService.SERVICE_NAME)
public interface ClientService {

	public static final String SERVICE_NAME = "service-member";
	
    @GetMapping(value = "findByClientId/{clientId}", produces = "application/json")
    public ClientDto findByClientId(@PathVariable("clientId") String clientId);
}
