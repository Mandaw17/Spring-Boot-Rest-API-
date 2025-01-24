package com.galimagroup.Backend.TestRecrutement.exception;

public class GlobalBadRequestException extends RuntimeException {
    public GlobalBadRequestException(String message) {
        super(message);
    }
}
