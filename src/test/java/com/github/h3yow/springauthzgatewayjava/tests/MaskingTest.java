package com.github.h3yow.springauthzgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.springauthzgatewayjava.util.Masking;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class MaskingTest {

    private static final Logger log = LoggerFactory.getLogger(MaskingTest.class);

    @Test
    void hideNeverRevealsSecret() {
        String password = "super-secret-password";
        String masked = Masking.hide(password);
        log.info("input=password(len={}) masked={}", password.length(), masked);
        assertEquals("***", masked);
        assertFalse(masked.contains(password));
    }

    @Test
    void prefixKeepsCorrelatableHintOnly() {
        String sessionId = "abcdef1234567890abcdef1234567890";
        String masked = Masking.prefix(sessionId);
        log.info("input=sessionId masked={}", masked);
        assertTrue(masked.startsWith("abcd"));
        assertFalse(masked.contains(sessionId));
        assertFalse(masked.contains("1234567890"));
    }

    @Test
    void shortIdentifierFullyHidden() {
        String masked = Masking.prefix("abc");
        log.info("input=short-id masked={}", masked);
        assertEquals("***", masked);
    }
}
