package nl._42.restsecure.autoconfigure.utils;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Locale;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import nl._42.restsecure.autoconfigure.form.FormValues;
import nl._42.restsecure.autoconfigure.form.LoginForm;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import org.apache.commons.io.IOUtils;

@Slf4j
public class FormUtil {

    private FormUtil() {throw new IllegalStateException("Utility class");}

    public static <T extends LoginForm> FormValues<T> getFormFromRequest(HttpServletRequest request, Class<T> clazz) {
        if (isMultipart(request)) {
            // A multipart body is never a JSON login form. Moreover, the servlet container has usually already
            // consumed the input stream while parsing the parts (e.g. Tomcat, during the CSRF token parameter
            // lookup), so calling getReader() here would throw an IllegalStateException.
            log.debug("Skipping request body of type '{}', continuing with an empty form", request.getContentType());
            return new FormValues<>("", instantiateForm(clazz));
        }
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String formJson = IOUtils.toString(request.getReader());
            T form;
            if (!formJson.isEmpty()) {
                form = objectMapper.readValue(formJson, clazz);
            } else {
                form = instantiateForm(clazz);
            }
            return new FormValues<>(formJson, form);
        } catch (JacksonException | IOException e) {
            log.warn("Could not use reader", e);
            return new FormValues<>("", instantiateForm(clazz));
        } catch (IllegalStateException e) {
            // getInputStream() was already called on this request (by the container or an earlier filter).
            log.warn("Request body was already consumed, continuing with an empty form: {}", e.getMessage());
            return new FormValues<>("", instantiateForm(clazz));
        }
    }

    private static boolean isMultipart(HttpServletRequest request) {
        String contentType = request.getContentType();
        return contentType != null && contentType.toLowerCase(Locale.ROOT).startsWith("multipart/");
    }

    private static <T extends LoginForm> T instantiateForm(Class<T> clazz) {
        try {
            Constructor<T> ctor = clazz.getConstructor();
            return ctor.newInstance();
        } catch (NoSuchMethodException | InvocationTargetException | InstantiationException | IllegalAccessException e) {
            throw new IllegalStateException("Could not find or instantiate with default constructor", e);
        }
    }
}
