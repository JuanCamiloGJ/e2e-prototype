package com.e2ew.e2e.keys.exceptions;

import org.springframework.http.HttpStatus;

public class AuthCryptoE2eException extends RuntimeException {

    private final HttpStatus httpStatus;

    public AuthCryptoE2eException(String message, HttpStatus status) {
        super(message);
        this.httpStatus = status;
    }

    public AuthCryptoE2eException(String message) {
        super(message);
        this.httpStatus = HttpStatus.BAD_REQUEST;
    }

    public AuthCryptoE2eException(String message, HttpStatus status, Throwable cause) {
        super(message, cause);
        this.httpStatus = status;
    }

    public int getHttpStatus() {
        return httpStatus.value();
    }
}
