package org.cloudfoundry.identity.uaa.security;

import org.cloudfoundry.identity.uaa.client.JdbcQueryableClientDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Set;

/** todo: this is ugly impl of redirection. RF further, by using redirect_uri from original request
 * @author rnuriev
 * @since 14.07.2016.
 */
public class UaaSavedRequestAwareAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    @Autowired
    JdbcQueryableClientDetailsService clientDetailsService;
    private RequestCache requestCache = new HttpSessionRequestCache();
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest == null) {
            clearAuthenticationAttributes(request);
            final String clientId = "hb";
            final List<ClientDetails> clientDetailses = clientDetailsService.query(String.format("client_id eq '%1$s'", clientId));
            if (clientDetailses != null && !clientDetailses.isEmpty()) {
                ClientDetails clientDetails = clientDetailses.get(0);
                final Set<String> registeredRedirectUri = clientDetails.getRegisteredRedirectUri();
                if (registeredRedirectUri != null && !registeredRedirectUri.isEmpty()) {
                    getRedirectStrategy().sendRedirect(request, response, registeredRedirectUri.iterator().next());
                    return;
                } else {
                    logger.warn("redirect_uri not specified for client_id:" + clientId);
                }
            }
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
