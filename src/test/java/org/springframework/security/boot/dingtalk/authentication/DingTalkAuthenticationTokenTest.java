package org.springframework.security.boot.dingtalk.authentication;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DingTalkAuthenticationTokenTest {

    @Test
    void scanCodeTokenRequiresAuthorityConstructorForTrustedState() {
        DingTalkScanCodeAuthenticationToken request = new DingTalkScanCodeAuthenticationToken("user", "code");
        assertFalse(request.isAuthenticated());
        assertThrows(IllegalArgumentException.class, () -> request.setAuthenticated(true));

        Collection<? extends GrantedAuthority> authorities =
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        DingTalkScanCodeAuthenticationToken trusted =
                new DingTalkScanCodeAuthenticationToken("user", "code", authorities);
        assertTrue(trusted.isAuthenticated());
        assertEquals(authorities, trusted.getAuthorities());
        trusted.eraseCredentials();
        assertNull(trusted.getCredentials());
    }

    @Test
    void temporaryCodeTokenRequiresAuthorityConstructorForTrustedState() {
        DingTalkTmpCodeAuthenticationToken request = new DingTalkTmpCodeAuthenticationToken("user", "code");
        assertFalse(request.isAuthenticated());
        assertThrows(IllegalArgumentException.class, () -> request.setAuthenticated(true));

        Collection<? extends GrantedAuthority> authorities =
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        DingTalkTmpCodeAuthenticationToken trusted =
                new DingTalkTmpCodeAuthenticationToken("user", "code", authorities);
        assertTrue(trusted.isAuthenticated());
        assertEquals(authorities, trusted.getAuthorities());
        trusted.eraseCredentials();
        assertNull(trusted.getCredentials());
    }
}
