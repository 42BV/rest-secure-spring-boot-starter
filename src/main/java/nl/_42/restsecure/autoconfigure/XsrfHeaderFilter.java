package nl._42.restsecure.autoconfigure;

import static org.springframework.web.util.WebUtils.getCookie;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * If no 'XSRF-TOKEN' cookie is found on the current request or if its value does not match the CsrfToken value in the CsrfTokenRepository 
 * a new one is created and put on the http response.
 */
public class XsrfHeaderFilter extends OncePerRequestFilter {

    public static final String COOKIE_XSRF_TOKEN = "XSRF-TOKEN";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String attributeValue = ((CsrfToken) request.getAttribute(CsrfToken.class.getName())).getToken();
        Cookie cookie = getCookie(request, COOKIE_XSRF_TOKEN);

        if (cookie == null || !cookie.getValue().equals(attributeValue)) {
            cookie = new Cookie(COOKIE_XSRF_TOKEN, attributeValue);
            cookie.setSecure(request.isSecure());
            cookie.setPath("/");
            response.addCookie(cookie);
        }
        filterChain.doFilter(request, response);
    }
}
