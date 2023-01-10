package nl._42.restsecure.autoconfigure.utils;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import javax.servlet.http.HttpServletRequest;

import nl._42.restsecure.autoconfigure.form.FormValues;
import nl._42.restsecure.autoconfigure.form.LoginForm;

import org.apache.commons.io.IOUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

public class FormUtil {

    private FormUtil() {throw new IllegalStateException("Utility class");}

    public static <T extends LoginForm> FormValues<T> getFormFromRequest(HttpServletRequest request, Class<T> clazz) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String formJson = IOUtils.toString(request.getReader());
            Constructor<?> ctor = clazz.getConstructor();
            T form = (T) ctor.newInstance();
            if (!formJson.isEmpty()) {
                form = objectMapper.readValue(formJson, clazz);
            }
            return new FormValues(formJson, form);
        } catch (IOException ioe) {
            throw new IllegalStateException("Could not use reader", ioe);
        } catch (NoSuchMethodException | InvocationTargetException | InstantiationException | IllegalAccessException e) {
            throw new RuntimeException("Could not find of make the default constructor", e);
        }
    }
}
