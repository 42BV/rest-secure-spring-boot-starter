package nl._42.restsecure.autoconfigure.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import nl._42.restsecure.autoconfigure.form.FormValues;
import nl._42.restsecure.autoconfigure.form.LoginForm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;

class FormUtilTest {

    // --- Valid JSON bodies ---

    @Test
    void getFormFromRequest_shouldParseJsonBody() {
        String json = "{\"username\":\"jane\",\"password\":\"secret\",\"verificationCode\":\"123456\"}";
        MockHttpServletRequest request = jsonRequest(json);

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals(json, formValues.formJson());
        assertEquals("jane", formValues.form().username);
        assertEquals("secret", formValues.form().password);
        assertEquals("123456", formValues.form().verificationCode);
    }

    @Test
    void getFormFromRequest_shouldParseJsonBody_whenNoContentTypeSet() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/authentication");
        request.setContent("{\"username\":\"jane\"}".getBytes(StandardCharsets.UTF_8));

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals("jane", formValues.form().username);
    }

    @Test
    void getFormFromRequest_shouldParseJsonBody_intoLoginFormSubclass() {
        MockHttpServletRequest request = jsonRequest("{\"username\":\"jane\",\"password\":\"secret\",\"tenant\":\"acme\"}");

        FormValues<ExtendedLoginForm> formValues = FormUtil.getFormFromRequest(request, ExtendedLoginForm.class);

        assertEquals("jane", formValues.form().username);
        assertEquals("secret", formValues.form().password);
        assertEquals("acme", formValues.form().tenant);
    }

    @Test
    void getFormFromRequest_shouldIgnoreUnknownJsonProperties() {
        MockHttpServletRequest request = jsonRequest("{\"username\":\"jane\",\"rememberMe\":true}");

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals("jane", formValues.form().username);
        assertNull(formValues.form().password);
    }

    @Test
    void getFormFromRequest_shouldLeaveFieldsNull_whenJsonObjectIsEmpty() {
        MockHttpServletRequest request = jsonRequest("{}");

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals("{}", formValues.formJson());
        assertEmptyForm(formValues.form());
    }

    // --- Empty body ---

    @Test
    void getFormFromRequest_shouldReturnEmptyForm_whenBodyIsEmpty() {
        MockHttpServletRequest request = jsonRequest("");

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals("", formValues.formJson());
        assertEmptyForm(formValues.form());
    }

    @Test
    void getFormFromRequest_shouldReturnEmptyForm_whenNoBodySet() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/authentication");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals("", formValues.formJson());
        assertEmptyForm(formValues.form());
    }

    // --- Invalid (non-JSON) bodies, as commonly sent by bots and scanners (14.1.0) ---

    @ParameterizedTest
    @ValueSource(strings = {
            "<?xml version=\"1.0\"?><login><username>admin</username><password>admin</password></login>",
            "<html><body><form><input name=\"username\" value=\"admin\"></form></body></html>",
            "<?php echo(md5(\"Hello World!\"));",
            "username=admin&password=admin",
            "just some plain text",
            "{\"username\":\"jane\",",          // truncated JSON
            "[{\"username\":\"jane\"}]",         // JSON array instead of object
            "\"jane\"",                          // JSON string instead of object
            "{\"username\":{\"nested\":true}}"   // wrong type for a field
    })
    void getFormFromRequest_shouldReturnEmptyForm_andNotThrow_whenBodyIsNotAJsonObject(String body) {
        MockHttpServletRequest request = jsonRequest(body);

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals("", formValues.formJson());
        assertEmptyForm(formValues.form());
    }

    @Test
    void getFormFromRequest_shouldReturnEmptyForm_whenXmlContentTypeAndBody() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/authentication");
        request.setContentType(MediaType.APPLICATION_XML_VALUE);
        request.setContent("<login><username>admin</username></login>".getBytes(StandardCharsets.UTF_8));

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals("", formValues.formJson());
        assertEmptyForm(formValues.form());
    }

    // --- Body cannot be read ---

    @Test
    void getFormFromRequest_shouldReturnEmptyForm_whenInputStreamAlreadyConsumed() {
        MockHttpServletRequest request = jsonRequest("{\"username\":\"jane\"}");
        // Simulate the servlet container (or an earlier filter) having consumed the body already.
        // getReader() then throws an IllegalStateException, which must not escape FormUtil.
        request.getInputStream();

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals("", formValues.formJson());
        assertEmptyForm(formValues.form());
    }

    @Test
    void getFormFromRequest_shouldReturnEmptyForm_whenReaderThrowsIOException() {
        HttpServletRequest request = new HttpServletRequestWrapper(jsonRequest("{\"username\":\"jane\"}")) {
            @Override
            public BufferedReader getReader() throws IOException {
                throw new IOException("connection reset");
            }
        };

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals("", formValues.formJson());
        assertEmptyForm(formValues.form());
    }

    // --- Multipart bodies are skipped without reading ---

    @ParameterizedTest
    @ValueSource(strings = {
            "multipart/form-data; boundary=----bot",
            "multipart/form-data",
            "MULTIPART/FORM-DATA; boundary=----bot",
            "multipart/mixed; boundary=----bot"
    })
    void getFormFromRequest_shouldReturnEmptyForm_whenBodyIsMultipart(String contentType) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/authentication");
        request.setContentType(contentType);
        request.setContent("------bot\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n------bot--\r\n"
                .getBytes(StandardCharsets.UTF_8));

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals("", formValues.formJson());
        assertEmptyForm(formValues.form());
    }

    @Test
    void getFormFromRequest_shouldNotTouchReader_whenBodyIsMultipart() {
        HttpServletRequest request = new HttpServletRequestWrapper(new MockHttpServletRequest("POST", "/authentication")) {
            @Override
            public String getContentType() {
                return "multipart/form-data; boundary=----bot";
            }

            @Override
            public BufferedReader getReader() {
                throw new AssertionError("getReader() must not be called for a multipart request");
            }
        };

        FormValues<LoginForm> formValues = FormUtil.getFormFromRequest(request, LoginForm.class);

        assertEquals("", formValues.formJson());
        assertEmptyForm(formValues.form());
    }

    // --- Form class cannot be instantiated ---

    @Test
    void getFormFromRequest_shouldThrow_whenFormClassHasNoDefaultConstructor() {
        MockHttpServletRequest request = jsonRequest("");

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> FormUtil.getFormFromRequest(request, FormWithoutDefaultConstructor.class));

        assertEquals("Could not find or instantiate with default constructor", exception.getMessage());
        assertInstanceOf(NoSuchMethodException.class, exception.getCause());
    }

    // --- Helpers ---

    private static MockHttpServletRequest jsonRequest(String body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/authentication");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        return request;
    }

    private static void assertEmptyForm(LoginForm form) {
        assertNull(form.username);
        assertNull(form.password);
        assertNull(form.verificationCode);
    }

    public static class ExtendedLoginForm extends LoginForm {
        public String tenant;
    }

    public static class FormWithoutDefaultConstructor extends LoginForm {
        public FormWithoutDefaultConstructor(String username) {
            this.username = username;
        }
    }
}
