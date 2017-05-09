package nl._42.restsecure.autoconfigure.components.errorhandling;

public class GenericErrorResult {

    private String errorCode;

    public GenericErrorResult(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
