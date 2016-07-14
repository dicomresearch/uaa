package org.cloudfoundry.identity.uaa.security.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Collection;

/**
 * @author rnuriev
 * @since 13.07.2016.
 */
public class UaaAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    final Logger logger = LoggerFactory.getLogger(getClass());
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();


    public static final String TEMP_LOGIN_SCOPE = "hb.login.temp";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        boolean isTempLogin = false;
        for (GrantedAuthority grantedAuthority : authorities) {
            final String authority = grantedAuthority.getAuthority();
            if (authority != null && authority.equals(TEMP_LOGIN_SCOPE)) {
                isTempLogin = true;
            }
        }
        if (!isTempLogin) {
            successRedirectHandler.onAuthenticationSuccess(request, response, authentication);
        } else {
            handle(request, response, authentication);
            clearAuthenticationAttributes(request);
        }
    }

    @Autowired
    SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler;

    protected void handle(HttpServletRequest request,
                          HttpServletResponse response, Authentication authentication) throws IOException {
        String targetUrl = determineTargetUrl(authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        redirectStrategy.sendRedirect(request, response, targetUrl);
    }

    /**
     */
    protected String determineTargetUrl(Authentication authentication) {
        // todo: temporary impl
        return "/change_login";
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }

    public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
        this.redirectStrategy = redirectStrategy;
    }

    protected RedirectStrategy getRedirectStrategy() {
        return redirectStrategy;
    }
}
