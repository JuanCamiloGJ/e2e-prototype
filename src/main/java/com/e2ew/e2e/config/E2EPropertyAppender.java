package com.e2ew.e2e.config;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;

public class E2EPropertyAppender implements EnvironmentPostProcessor {

    private static final String KEY = "security.paths.no-auth-access";
    private static final String VALUE_TO_ADD = "/.internal/key-rotation";
    private static final String PS_NAME = "e2e-appender";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        // 1) Leer la propiedad existente como lista (funciona con coma o YAML en lista)
        String[] existing = Binder.get(environment)
                .bind(KEY, String[].class)
                .orElse(new String[0]);

        // 2) Fusionar + evitar duplicados
        LinkedHashSet<String> merged = new LinkedHashSet<>(Arrays.asList(existing));
        merged.add(VALUE_TO_ADD);

        // 3) Publicar el valor final como UNA MISMA propiedad (con mayor prioridad)
        Map<String, Object> props = Map.of(KEY, String.join(",", merged));

        MutablePropertySources sources = environment.getPropertySources();
        // elimina anterior si ya lo agregaste antes (evita duplicados al recargar)
        if (sources.contains(PS_NAME)) {
            sources.remove(PS_NAME);
        }
        // addFirst = toma precedencia sobre application.properties, es la *misma* propiedad final
        sources.addFirst(new MapPropertySource(PS_NAME, props));

    }
}
