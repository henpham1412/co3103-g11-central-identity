package vn.edu.hcmut.co3103.identity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@Configuration
@EnableScheduling
public class PasswordRecoveryConfig {
    @Bean
    public ThreadPoolTaskExecutor accountNotificationExecutor() {
        ThreadPoolTaskExecutor executor = executor(2, "account-notice-");
        executor.setQueueCapacity(100);
        return executor;
    }

    @Bean
    public ThreadPoolTaskExecutor recoveryIssuanceExecutor() { return executor(2, "recovery-issue-"); }

    @Bean
    public ThreadPoolTaskExecutor recoveryDeliveryExecutor() { return executor(4, "recovery-smtp-"); }

    private ThreadPoolTaskExecutor executor(int size, String prefix) {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(size);
        executor.setMaxPoolSize(size);
        executor.setQueueCapacity(0); // PostgreSQL owns the backlog, never an unbounded memory queue.
        executor.setThreadNamePrefix(prefix);
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        return executor;
    }
}
