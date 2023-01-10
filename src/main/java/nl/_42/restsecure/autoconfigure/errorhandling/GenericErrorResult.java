package nl._42.restsecure.autoconfigure.errorhandling;

/**
 * Represents the json object that is set as http response body when an exception is thrown.
 */
public class GenericErrorResult {

    private final String errorCode;

    public GenericErrorResult(String code) {
        this.errorCode = code;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
