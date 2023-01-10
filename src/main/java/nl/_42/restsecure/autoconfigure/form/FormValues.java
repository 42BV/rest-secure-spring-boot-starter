package nl._42.restsecure.autoconfigure.form;

public record FormValues<F extends LoginForm>(String formJson, F form) {
}