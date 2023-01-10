package nl._42.restsecure.autoconfigure.form;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginForm {

    public String username;
    public String password;
    public boolean rememberMe;
    public String verificationCode;
}