package nl._42.restsecure.autoconfigure.authentication.mfa;

import static nl._42.restsecure.autoconfigure.authentication.mfa.MfaAuthenticationProvider.DETAILS_MFA_SETUP_REQUIRED;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;

import org.springframework.http.ProblemDetail;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A {@link GenericFilterBean} that denies requests when the user is obliged to set up MFA but hasn't done so.
 */
public class MfaSetupRequiredFilter extends GenericFilterBean {

    private static final String SERVER_MFA_SETUP_REQUIRED_ERROR = "SERVER.MFA_SETUP_REQUIRED_ERROR";

    @Getter
    private final List<RequestMatcher> excludedRequests = new ArrayList<>();

    @Getter
    private final List<BiFunction<ServletRequest, ServletResponse, Boolean>> exclusionChecks = new ArrayList<>();

    @Setter
    private ObjectMapper objectMapper;

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(this.objectMapper, "A ObjectMapper must be set");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // We only perform this filter if the authentication contains the correct details.
        if (authentication == null || !DETAILS_MFA_SETUP_REQUIRED.equals(authentication.getDetails())) {
            continueWithFilterChain(request, response, chain);
            return;
        }

        // Required to allow access to public endpoints or endpoints mandatory to load the MFA setup page.
        if (excludedRequests.stream().anyMatch(r -> r.matches(((HttpServletRequest) request)))) {
            continueWithFilterChain(request, response, chain);
            return;
        }

        // If any other check indicates that the MFA setup should not be performed, do not send the error.
        if (exclusionChecks.stream().anyMatch(exclusion -> exclusion.apply(request, response))) {
            continueWithFilterChain(request, response, chain);
            return;
        }

        sendMfaSetupRequiredError(response);
    }

    private void sendMfaSetupRequiredError(ServletResponse response) {
        try {
            // Return access denied status with "mfa not setup" as the reason.
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;

            httpServletResponse.setStatus(FORBIDDEN.value());
            response.setContentType(APPLICATION_JSON_VALUE);
            ProblemDetail pd = ProblemDetail.forStatusAndDetail(FORBIDDEN, "MFA setup incorrect");
            pd.setProperty("errorCode", SERVER_MFA_SETUP_REQUIRED_ERROR);
            objectMapper.writeValue(httpServletResponse.getWriter(), pd);
            httpServletResponse.getWriter().flush();
        } catch (IOException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private void continueWithFilterChain(ServletRequest request, ServletResponse response, FilterChain chain) {
        try {
            chain.doFilter(request, response);
        } catch (IOException | ServletException exception) {
            throw new IllegalStateException(exception);
        }
    }
}

