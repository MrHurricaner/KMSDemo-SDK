package com.juzix.kms;

import java.security.SecureRandom;

public class SecureRandomUtils {

    private static final SecureRandom SECURE_RANDOM;

    static {
        SECURE_RANDOM = new SecureRandom();
    }

    public static SecureRandom secureRandom() {
        return SECURE_RANDOM;
    }

    private SecureRandomUtils() { }
}
