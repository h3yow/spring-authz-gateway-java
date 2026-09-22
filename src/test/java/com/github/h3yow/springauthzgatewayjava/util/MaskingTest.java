package com.github.h3yow.springauthzgatewayjava.util;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class MaskingTest {

    private static final Logger log = LoggerFactory.getLogger(MaskingTest.class);

    @Test
    void maskHidesRawSecretButKeepsStableCorrelation() {
        String secret = "super-secret-token-value";
        String masked = Masking.mask(secret);
        log.info("input=[{}] masked=[{}]", secret, masked);
        assertFalse(masked.contains(secret), "脱敏结果不得包含原文");
        assertTrue(masked.startsWith("sha256:"), "应保留散列关联标识");
        assertEquals(masked, Masking.mask(secret), "同一输入的关联标识必须稳定");
        assertNotEquals(Masking.mask("other"), masked, "不同输入的关联标识应不同");
    }

    @Test
    void maskHandlesNullAndEmpty() {
        log.info("input=null masked=[{}]", Masking.mask(null));
        assertEquals("<empty>", Masking.mask(null));
        assertEquals("<empty>", Masking.mask(""));
    }
}
