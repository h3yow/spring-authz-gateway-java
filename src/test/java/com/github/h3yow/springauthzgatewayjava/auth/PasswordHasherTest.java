package com.github.h3yow.springauthzgatewayjava.auth;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class PasswordHasherTest {

    private static final Logger log = LoggerFactory.getLogger(PasswordHasherTest.class);
    private final PasswordHasher hasher = new PasswordHasher();

    @Test
    void hashThenVerifyRoundTrip() {
        char[] password = "correct horse battery staple".toCharArray();
        String stored = hasher.hash(password);
        log.info("input=password(len={}) storedHash=[{}]", password.length, stored);
        assertTrue(stored.startsWith("pbkdf2$"), "散列需带算法与参数标识");
        assertFalse(stored.contains(new String(password)), "存储值不得包含明文");
        assertTrue(hasher.verify(password, stored));
        assertFalse(hasher.verify("wrong".toCharArray(), stored));
    }

    @Test
    void hashesAreSaltedAndUnique() {
        String h1 = hasher.hash("same".toCharArray());
        String h2 = hasher.hash("same".toCharArray());
        log.info("same input -> h1=[{}] h2=[{}]", h1, h2);
        assertNotEquals(h1, h2, "随机盐使同口令散列不同");
    }

    @Test
    void verifyRejectsMalformedStoredHash() {
        log.info("input=malformed stored hash");
        assertFalse(hasher.verify("x".toCharArray(), "not-a-hash"));
        assertFalse(hasher.verify("x".toCharArray(), null));
        assertFalse(hasher.verify(null, "pbkdf2$1$aa$bb"));
    }
}
