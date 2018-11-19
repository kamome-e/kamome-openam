/*
 * DO NOT REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2013 ForgeRock AS All rights reserved.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions copyright [year] [name of copyright owner]"
 */
package org.forgerock.openam.oauth2.openid;

import org.codehaus.jackson.annotate.JsonValue;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.shared.OAuth2Constants;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openam.oauth2.exceptions.OAuthProblemException;
import org.forgerock.openam.oauth2.model.CustomSignedJwt;
import org.forgerock.openam.oauth2.utils.OAuth2Utils;
import org.restlet.representation.Representation;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class EndSession extends ServerResource {

    private SSOTokenManager ssoTokenManager = null;

    public EndSession () {
        try {
            ssoTokenManager = SSOTokenManager.getInstance();
        } catch (Exception e) {
            OAuth2Utils.DEBUG.error("Unable to get SsoTokenManager", e);
            throw OAuthProblemException.OAuthError.SERVER_ERROR.handle(null, "Unable to get SsoTokenManager");
        }
    }

    public EndSession (SSOTokenManager ssoTokenManager) {
        this.ssoTokenManager = ssoTokenManager;
    }

    @Get
    public Representation endSession() {
        String id_token = OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Params.END_SESSION_ID_TOKEN_HINT, String.class);
        if (id_token == null || id_token.isEmpty()){
            OAuth2Utils.DEBUG.warning("No id_token_hint parameter supplied to the endSession endpoint");
            throw OAuthProblemException.OAuthError.BAD_REQUEST.handle(null, "The endSesison endpoint requires an id_token_hint parameter");
        }
        JwtReconstruction jwtReconstruction = new JwtReconstruction();
        CustomSignedJwt jwt = jwtReconstruction.reconstructJwt(id_token, CustomSignedJwt.class);

        JwtClaimsSet claims = jwt.getClaimsSet();
        String sessionId = (String) claims.getClaim(OAuth2Constants.JWTTokenParams.OPS);
        if (sessionId == null) {
            sessionId = (String) claims.getClaim(OAuth2Constants.JWTTokenParams.LEGACY_OPS);
        }

        destroySession(sessionId);
        return null;
    }

    private void destroySession(String sessionId){
        try {
            SSOToken token = ssoTokenManager.createSSOToken(sessionId);
            ssoTokenManager.destroyToken(token);
        } catch (Exception e) {
            OAuth2Utils.DEBUG.error("Unable to get SsoTokenManager", e);
            throw OAuthProblemException.OAuthError.SERVER_ERROR.handle(null, "Unable to get SsoTokenManager");
        }

    }
}
