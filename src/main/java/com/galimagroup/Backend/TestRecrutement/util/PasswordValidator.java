package com.galimagroup.Backend.TestRecrutement.util;

import com.galimagroup.Backend.TestRecrutement.exception.GlobalBadRequestException;
import com.galimagroup.Backend.TestRecrutement.exception.ProductNotFoundException;

import java.util.regex.Pattern;

public class PasswordValidator {

    private static final int MIN_LENGTH = 8;
    private static final String UPPERCASE_REGEX = ".*[A-Z].*";
    private static final String LOWERCASE_REGEX = ".*[a-z].*";
    private static final String DIGIT_REGEX = ".*[0-9].*";
    private static final String SPECIAL_CHAR_REGEX = ".*[!@#$%^&*(),.?\":{}|<>].*";

    public static boolean isValid(String password) {
        if (password == null || password.length() < MIN_LENGTH) {
            return false; // Check minimum length
        }
        if (!Pattern.matches(UPPERCASE_REGEX, password)) {
            return false; // Check for at least one uppercase letter
        }
        if (!Pattern.matches(LOWERCASE_REGEX, password)) {
            return false; // Check for at least one lowercase letter
        }
        if (!Pattern.matches(DIGIT_REGEX, password)) {
            return false; // Check for at least one digit
        }
        if (!Pattern.matches(SPECIAL_CHAR_REGEX, password)) {
            return false; // Check for at least one special character
        }
        return true;
    }

    public static String getValidationMessage(String password, String passwordConfirmation) {
        if (password == null || password.length() < MIN_LENGTH) {
            throw new RuntimeException("Password must be at least " + MIN_LENGTH + " characters long.");
        }
        if (!Pattern.matches(UPPERCASE_REGEX, password)) {
            throw new GlobalBadRequestException("Password must contain at least one uppercase letter.");
        }
        if (!Pattern.matches(LOWERCASE_REGEX, password)) {
            throw new GlobalBadRequestException("Password must contain at least one lowercase letter.");
        }
        if (!Pattern.matches(DIGIT_REGEX, password)) {
            throw new GlobalBadRequestException("Password must contain at least one digit.");
        }
        if (!Pattern.matches(SPECIAL_CHAR_REGEX, password)) {
            throw new GlobalBadRequestException("Password must contain at least one special character.");
        }
        if (!password.equals(passwordConfirmation)) {
            throw new GlobalBadRequestException("The two passwords don't match.");
        }
        return null; // No errors
    }
}
