package com.e2ew.e2e.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cloud.consul.serviceregistry.ConsulRegistration;
import org.springframework.cloud.consul.serviceregistry.ConsulRegistrationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.ecwid.consul.v1.ConsulClient;

@Configuration
public class ConsulRegistrationConfig {

    @Bean
    ConsulRegistrationCustomizer addCryptoMeta() {
        return (ConsulRegistration registration) -> {
            /*
             * Añade una metainformación y una etiqueta al servicio registrado en Consul
             * indicando que tiene habilitado el cifrado.
             */
            registration.getService().getMeta().put("crypto", "enabled");
            registration.getService().getTags().add("crypto-enabled");
        };
    }

    @Bean
    @ConditionalOnMissingBean
    public ConsulClient consulClient(
            @Value("${spring.cloud.consul.host:localhost}") String host,
            @Value("${spring.cloud.consul.port:8500}") int port
    ) {
        return new ConsulClient(host, port);
    }
}
