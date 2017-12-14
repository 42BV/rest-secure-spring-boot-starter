package nl._42.restsecure.autoconfigure.components.errorhandling;

/**
 * Represents the json object that is set as http response body when an exception is thrown.
 */
public class GenericErrorResult {

    private String errorCode;

    public GenericErrorResult(String code) {
        this.errorCode = code;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
