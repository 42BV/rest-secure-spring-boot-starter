package nl._42.restsecure.autoconfigure.errorhandling;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import nl._42.restsecure.autoconfigure.form.LoginForm;
import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;

/**
 * The username is personal data: a failed login is logged at WARN with a non-sensitive id at most, never the username.
 */
class LogUtilTest {

    private final Logger logger = (Logger) LoggerFactory.getLogger(LogUtilTest.class);
    private final Logger handlerLogger = (Logger) LoggerFactory.getLogger(RestAccessDeniedHandler.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private Level previousLevel;
    private Level previousHandlerLevel;

    @BeforeEach
    void captureLog() {
        previousLevel = logger.getLevel();
        previousHandlerLevel = handlerLogger.getLevel();
        logger.setLevel(Level.INFO);
        handlerLogger.setLevel(Level.INFO);
        appender.start();
        logger.addAppender(appender);
        handlerLogger.addAppender(appender);
    }

    @AfterEach
    void releaseLog() {
        logger.detachAppender(appender);
        handlerLogger.detachAppender(appender);
        logger.setLevel(previousLevel);
        handlerLogger.setLevel(previousHandlerLevel);
    }

    private List<String> lines() {
        List<String> lines = appender.list.stream().map(e -> e.getLevel() + " " + e.getFormattedMessage()).toList();
        assertThat(lines).noneMatch(line -> line.contains("person@example.com"));
        return lines;
    }

    private static LoginForm form(String username) {
        LoginForm form = new LoginForm();
        form.username = username;
        return form;
    }

    @Test
    void failure_withoutRequestOrResolver_isLoggedWithoutUser() {
        LogUtil.logAuthenticationFailure(logger, form("person@example.com"), new BadCredentialsException("Bad credentials"));

        assertThat(lines()).containsExactly("WARN Authentication failure! Bad credentials");
    }

    @Test
    void failure_withResolverReturningNull_isLoggedAsUnknownUser() {
        LogUtil.logAuthenticationFailure(logger, form("person@example.com"), new BadCredentialsException("Bad credentials"), null, username -> null);

        assertThat(lines()).containsExactly("WARN Authentication failure for an unknown user! Bad credentials");
    }

    @Test
    void resolveLogId_withoutResolverOrUsername_isEmpty() {
        assertThat(LogUtil.resolveLogId(logger, null, "person@example.com")).isEmpty();
        assertThat(LogUtil.resolveLogId(logger, username -> Optional.of("7"), null)).isEmpty();
        assertThat(LogUtil.resolveLogId(logger, username -> Optional.of("7"), "person@example.com")).contains("7");
    }

    @Test
    void accessDeniedHandler_withoutResolver_logsWithClientAddressOnly() throws Exception {
        RestAccessDeniedHandler handler = new RestAccessDeniedHandler(new GenericErrorHandler(JsonMapper.builder().build()));
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/test/forbidden");
        request.setContent("{\"username\": \"person@example.com\", \"password\": \"password\"}".getBytes());
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handle(request, response, new AccessDeniedException("Access Denied"));

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(lines()).containsExactly("WARN Authentication failure from 127.0.0.1! Access Denied");
    }
}
