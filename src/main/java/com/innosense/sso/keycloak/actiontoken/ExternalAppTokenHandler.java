/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.innosense.sso.keycloak.actiontoken;

import org.keycloak.Config.Scope;
import org.keycloak.TokenVerifier;
import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.*;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64;
import org.keycloak.events.*;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import java.io.IOException;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;
import static org.keycloak.services.resources.LoginActionsService.AUTHENTICATE_PATH;

/**
 * @author Harijaona Ravelondrina <hravelondrina@gmail.com>
 * 
 */
public class ExternalAppTokenHandler extends AbstractActionTokenHandler<ExternalAppActionToken> {

    public static final String QUERY_PARAM_APP_TOKEN = "appToken";

    public static final String INITIATED_BY_ACTION_TOKEN_EXT_APP = "INITIATED_BY_ACTION_TOKEN_THIRD_APP";

    private static final Logger LOG = Logger.getLogger(ExternalAppTokenHandler.class);

    private SecretKeySpec hmacSecretKeySpec = null;

    public ExternalAppTokenHandler() {
        super(
          ExternalAppActionToken.TOKEN_TYPE,
          ExternalAppActionToken.class,
          Messages.INVALID_REQUEST,
          EventType.EXECUTE_ACTION_TOKEN,
          Errors.INVALID_REQUEST
        );
    }

    private boolean isApplicationTokenValid(
      ExternalAppActionToken token,
      ActionTokenContext<ExternalAppActionToken> tokenContext
    ) throws VerificationException {
        String appTokenString = tokenContext.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN);

        LOG.infof("isApplicationTokenValid %s", appTokenString);

        TokenVerifier.create(appTokenString, JsonWebToken.class)
          .secretKey(hmacSecretKeySpec)
          .verify();

        return true;
    }

    @Override
    public Predicate<? super ExternalAppActionToken>[] getVerifiers(ActionTokenContext<ExternalAppActionToken> tokenContext) {

        LOG.infof("getVerifiers %s", tokenContext.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN));

        return TokenUtils.predicates(
          // Check that the app token is set in query parameters
          t -> tokenContext.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN) != null,

          // Validate correctness of the app token
          t -> isApplicationTokenValid(t, tokenContext)
        );
    }

    @Override
    public Response handleToken(ExternalAppActionToken token, ActionTokenContext<ExternalAppActionToken> tokenContext) {
        // Continue with the authenticator action
        tokenContext.getAuthenticationSession().setAuthNote(INITIATED_BY_ACTION_TOKEN_EXT_APP, "true");
        tokenContext.getAuthenticationSession().getAuthenticatedUser();
        
        return tokenContext.processFlow(true, AUTHENTICATE_PATH, tokenContext.getRealm().getBrowserFlow(), null, new AuthenticationProcessor());
    }

    

    @Override
    public String getAuthenticationSessionIdFromToken(ExternalAppActionToken token, ActionTokenContext<ExternalAppActionToken> tokenContext,
      AuthenticationSessionModel currentAuthSession) {
        // always join current authentication session
        final String id = currentAuthSession == null
          ? null
          : AuthenticationSessionCompoundId.fromAuthSession(currentAuthSession).getEncodedId();

        LOG.infof("Returning %s", id);

        return id;
    }

    @Override
    public void init(Scope config) {
        final String hmacSecret = config.get("hmacSecret", null);
        
        if (hmacSecret == null) {
            throw new RuntimeException("You have to configure HMAC secret");
        }

        try {
            this.hmacSecretKeySpec = new SecretKeySpec(Base64.decode(hmacSecret), "HmacSHA256");
        } catch (IOException ex) {
            throw new RuntimeException("Cannot decode HMAC secret from string", ex);
        }
    }
}
