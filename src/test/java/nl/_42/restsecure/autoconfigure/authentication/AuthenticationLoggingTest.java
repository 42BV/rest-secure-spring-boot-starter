package nl._42.restsecure.autoconfigure.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import nl._42.restsecure.autoconfigure.AbstractApplicationContextTest;
import nl._42.restsecure.autoconfigure.RestAuthenticationFilter;
import nl._42.restsecure.autoconfigure.test.ActiveUserConfig;
import nl._42.restsecure.autoconfigure.test.NoopPasswordEncoderConfig;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;

/**
 * The username is personal data: a login is logged at INFO or WARN with the log id of the user at most, never the
 * username, and logging never breaks a login.
 */
class AuthenticationLoggingTest extends AbstractApplicationContextTest {

    private static final String GOOD = "{\"username\": \"person@example.com\", \"password\": \"password\"}";
    private static final String WRONG = "{\"username\": \"person@example.com\", \"password\": \"wrong\"}";

    private final Logger logger = (Logger) LoggerFactory.getLogger(RestAuthenticationFilter.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private Level previousLevel;

    @BeforeEach
    void captureLog() {
        previousLevel = logger.getLevel();
        logger.setLevel(Level.INFO);
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void releaseLog() {
        logger.detachAppender(appender);
        logger.setLevel(previousLevel);
    }

    private List<String> lines() {
        List<String> lines = appender.list.stream().map(e -> e.getLevel() + " " + e.getFormattedMessage()).toList();
        assertThat(lines).noneMatch(line -> line.contains("person@example.com"));
        return lines;
    }

    @Test
    void success_withoutLogId_isLoggedWithoutUser() throws Exception {
        getWebClient(ActiveUserConfig.class, NoopPasswordEncoderConfig.class)
                .perform(post("/authentication").with(anonymous()).content(GOOD))
                .andExpect(status().isOk());

        assertThat(lines()).containsExactly("INFO Authentication succeeded");
    }

    @Test
    void success_withLogId_isLoggedWithThatId() throws Exception {
        getWebClient(LogIdUserConfig.class, NoopPasswordEncoderConfig.class)
                .perform(post("/authentication").with(anonymous()).content(GOOD))
                .andExpect(status().isOk());

        assertThat(lines()).containsExactly("INFO Authentication succeeded for user 42");
    }

    @Test
    void success_withFailingLogId_stillLogsInTheUser() throws Exception {
        getWebClient(FailingLogIdUserConfig.class, NoopPasswordEncoderConfig.class)
                .perform(post("/authentication").with(anonymous()).content(GOOD))
                .andExpect(status().isOk());

        assertThat(lines()).containsExactly("INFO Authentication succeeded");
    }

    @Test
    void failure_isLoggedWithClientAddressOnly() throws Exception {
        getWebClient(ActiveUserConfig.class, NoopPasswordEncoderConfig.class)
                .perform(post("/authentication").with(anonymous()).content(WRONG))
                .andExpect(status().isUnauthorized());

        assertThat(lines()).containsExactly("WARN Authentication failure from 127.0.0.1! Bad credentials");
    }

    private static RegisteredUser user(String logId, boolean failing) {
        return new RegisteredUser() {
            @Override
            public String getUsername() {
                return "person@example.com";
            }

            @Override
            public String getPassword() {
                return "password";
            }

            @Override
            public Set<String> getAuthorities() {
                return Collections.singleton("ROLE_ADMIN");
            }

            @Override
            public String getLogId() {
                if (failing) {
                    throw new IllegalStateException("no id");
                }
                return logId;
            }
        };
    }

    // No @Configuration: registered only by the tests that name it, never picked up by component scanning.
    static class LogIdUserConfig {
        @Bean
        public AbstractUserDetailsService<RegisteredUser> userDetailsService() {
            return new AbstractUserDetailsService<>() {
                @Override
                public RegisteredUser findUserByUsername(String username) {
                    return user("42", false);
                }
            };
        }
    }

    // No @Configuration: registered only by the tests that name it, never picked up by component scanning.
    static class FailingLogIdUserConfig {
        @Bean
        public AbstractUserDetailsService<RegisteredUser> userDetailsService() {
            return new AbstractUserDetailsService<>() {
                @Override
                public RegisteredUser findUserByUsername(String username) {
                    return user(null, true);
                }
            };
        }
    }
}
