package com.metranet.finbox.core.exception;

import com.auth0.jwt.exceptions.JWTVerificationException;

public class AuthException extends JWTVerificationException {

    /**
     *  Generated Serial Version Id
     */
    private static final long serialVersionUID = 1778454713721064405L;

    public AuthException(String message) {
        super(message);
    }
}