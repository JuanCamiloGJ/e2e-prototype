package com.e2ew.e2e.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

@Configuration
public class KeyRotationConfig {

    @Bean(name = "keyRotationTaskScheduler")
    @ConditionalOnMissingBean(name = "keyRotationTaskScheduler")
    public TaskScheduler keyRotationTaskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(2);
        scheduler.setThreadNamePrefix("key-rotation-");
        scheduler.initialize();
        return scheduler;
    }

}
