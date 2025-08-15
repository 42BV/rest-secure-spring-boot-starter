package nl._42.restsecure.autoconfigure.utils;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import jakarta.servlet.http.HttpServletRequest;
import nl._42.restsecure.autoconfigure.form.FormValues;
import nl._42.restsecure.autoconfigure.form.LoginForm;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

public class FormUtil {

    private static final Logger log = LoggerFactory.getLogger(FormUtil.class);

    private FormUtil() {throw new IllegalStateException("Utility class");}

    public static <T extends LoginForm> FormValues<T> getFormFromRequest(HttpServletRequest request, Class<T> clazz) {
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
        } catch (IOException ioe) {
            log.warn("Could not use reader", ioe);
            return new FormValues<>("", instantiateForm(clazz));
        }
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
