/*
 * DO NOT REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2012-2014 ForgeRock Inc. All rights reserved.
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
 * "Portions Copyrighted [year] [name of copyright owner]"
 */

package org.forgerock.restlet.ext.oauth2.provider;

import java.io.IOException;
import java.security.AccessController;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.forgerock.openam.oauth2.exceptions.OAuthProblemException;
import org.forgerock.openam.oauth2.model.BearerToken;
import org.forgerock.openam.oauth2.model.CoreToken;
import org.forgerock.openam.oauth2.provider.OAuth2TokenStore;
import org.forgerock.openam.oauth2.provider.Scope;
import org.forgerock.openam.oauth2.utils.OAuth2Utils;
import org.forgerock.restlet.ext.oauth2.consumer.AccessTokenExtractor;
import org.forgerock.restlet.ext.oauth2.consumer.AccessTokenValidator;
import org.forgerock.restlet.ext.oauth2.consumer.BearerTokenExtractor;
import org.restlet.Client;
import org.restlet.Context;
import org.restlet.Response;
import org.restlet.data.CacheDirective;
import org.restlet.data.Form;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Status;
import org.restlet.engine.header.Header;
import org.restlet.engine.header.HeaderConstants;
import org.restlet.ext.jackson.JacksonRepresentation;
import org.restlet.representation.Representation;
import org.restlet.resource.ClientResource;
import org.restlet.resource.Get;
import org.restlet.resource.ResourceException;
import org.restlet.resource.ServerResource;
import org.restlet.util.Series;

import com.iplanet.sso.SSOToken;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.OAuth2Constants;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;

/**
 * Validates the token and returns to the subject the tokeninfo and scope evaluation if it is used.
 * <p/>
 *
 * @author Laszlo Hordos
 */
public class ValidationServerResource extends ServerResource implements
        AccessTokenValidator<BearerToken> {

    private OAuth2TokenStore tokenStore = null;
    private Reference validationServerRef;

    private final static String CONNECTION_TIMEOUT_MS = "30000";
    private final static String SOCKET_TIMEOUT = "socketTimeout";

    public ValidationServerResource() {
        this.validationServerRef = null;
    }

    public ValidationServerResource(Context context, Reference validationServerRef) {
        tokenStore = OAuth2Utils.getTokenStore(context);
        if (null == tokenStore) {
            OAuth2Utils.DEBUG.error("ValidationServerResource::Unable to get token store");
            throw new ResourceException(Status.SERVER_ERROR_INTERNAL,
                    "Missing required context attribute: " + OAuth2TokenStore.class.getName());
        }
        this.validationServerRef = validationServerRef;
        init(context, null, null);
    }

    /**
     * Set-up method that can be overridden in order to initialize the state of
     * the resource. By default it does nothing.
     *
     * @see #init(org.restlet.Context, org.restlet.Request,
     *      org.restlet.Response)
     */
    protected void doInit() throws ResourceException {
        if (null != getRequest() && null != getContext()) {
            tokenStore = OAuth2Utils.getTokenStore(getContext());
            if (null == tokenStore) {
                OAuth2Utils.DEBUG.error("ValidationServerResource::Unable to get token store");
                throw new ResourceException(Status.SERVER_ERROR_INTERNAL,
                        "Missing required context attribute: " + OAuth2TokenStore.class.getName());
            }
        }
    }

    @Get()
    public Representation validate() throws ResourceException {
        if (OAuth2Utils.DEBUG.messageEnabled()){
            OAuth2Utils.DEBUG.message("ValidationServerResource::In Validator resource");
        }

        OAuthProblemException error = null;
        Map<String, Object> response = new HashMap<String, Object>();
        Scope scopeClass = null;

        try {
            Form call = getQuery();
            Map<String, Object> tokenMap = AccessTokenExtractor.extractToken(getRequest());
            String token = (String) tokenMap.get("access_token");

            if (null == token) {
                OAuth2Utils.DEBUG.error("ValidationServerResource::Missing access token in request");
                error =
                        OAuthProblemException.OAuthError.INVALID_REQUEST.handle(getRequest(),
                                "Missing access_token");
            } else {
                CoreToken t = tokenStore.readAccessToken(token);

                if (t == null) {
                    OAuth2Utils.DEBUG.error("ValidationServerResource::Unable to read token from token store for id: " + token);
                    error = OAuthProblemException.OAuthError.INVALID_TOKEN.handle(getRequest());
                } else {
                    String pluginClass = getPluginClass(t.getRealm());
                    //instantiate plugin class
                    scopeClass = (Scope) Class.forName(pluginClass).newInstance();

                    //call plugin class init
                    if (OAuth2Utils.DEBUG.messageEnabled()){
                        OAuth2Utils.DEBUG.message("ValidationServerResource::In Validator resource - got token = " + t);
                    }

                    if (t.isExpired()) {
                        error = OAuthProblemException.OAuthError.EXPIRED_TOKEN.handle(getRequest());
                        OAuth2Utils.DEBUG.error("ValidationServerResource::Should response and refresh the token");
                    }

                    if (error == null) {
                        //call plugin class.process
                        Map <String, Object> scopeEvaluation = scopeClass.evaluateScope(t);
                        response.putAll(t.getTokenInfo());
                        response.putAll(scopeEvaluation);
                    }


                }

            }
        } catch (OAuthProblemException e) {
            OAuth2Utils.DEBUG.error("ValidationServerResource::Error occurred during validate", e);
            error = e;
        } catch (Exception e){
            OAuth2Utils.DEBUG.error("ValidationServerResource::Error occurred during validate", e);
            error = OAuthProblemException.OAuthError.SERVER_ERROR.handle(getRequest(),
                    e.getMessage());
        }

        if (error != null) {
            throw error;
        }

        // Sets the no-store Cache-Control header
        getResponse().getCacheDirectives().add(CacheDirective.noCache());
        getResponse().getCacheDirectives().add(CacheDirective.noStore());
        return new JacksonRepresentation<Map>(response);
    }

    private void setConnectionClose(ClientResource clientResource) {
        @SuppressWarnings("unchecked")
        Series<Header> headers = (Series<Header>) clientResource.getRequestAttributes().get(HeaderConstants.ATTRIBUTE_HEADERS);
        if (headers == null) {
            headers = new Series<Header>(Header.class);
            clientResource.getRequestAttributes().put(HeaderConstants.ATTRIBUTE_HEADERS, headers);
        }
        headers.add(HeaderConstants.HEADER_CONNECTION, "close");
    }

    @Override
    public BearerToken verify(BearerToken token) throws OAuthProblemException {
        Reference reference = new Reference(validationServerRef);
        reference.addQueryParameter(OAuth2Constants.Params.ACCESS_TOKEN, token.getTokenID());
        Client client = null;
        Response response = null;
        try {
            client = new Client(new Context(), validationServerRef.getSchemeProtocol());
            ClientResource clientResource = new ClientResource(reference.toUri()) {
                @Override
                public void doError(Status errorStatus) {
                    // HTTPステータス・コードがエラーとなった場合に呼び出される処理をオーバーライドする。
                    // デフォルトの処理ではここで例外を投げるが、ここでは何もせず
                    // 呼び出し元でエラーハンドリングを行うように処理を変更する。
                    // ここで例外を投げてしまうとレスポンスを消費する機会がないため
                    // コネクションが閉じられずソケットのCLOSE_WAITが残ってしまうため。
                    // （呼び出し元ではエラーの場合もレスポンスを消費する必要がある）
                }
            };
            setConnectionClose(clientResource);
            clientResource.setNext(client);
            client.getContext().getParameters().set(SOCKET_TIMEOUT, CONNECTION_TIMEOUT_MS);
            clientResource.get();

            // Actually handle the call
            response = clientResource.getResponse();
            if (response.getStatus().isError()) {
                throw new ResourceException(response.getStatus());
            }

            try {
                // Throws OAuthProblemException
                Map remoteToken = BearerTokenExtractor.extractToken(response);

                Object o = remoteToken.get(OAuth2Constants.Token.OAUTH_ACCESS_TOKEN);
                if (o != null){
                    return (BearerToken) tokenStore.readAccessToken(o.toString());
                }

                return null;
            } catch (OAuthProblemException e) {
                OAuth2Utils.DEBUG.error("ValidationServerResource::Error occurred during token verify", e);
                throw e;
            } catch (ResourceException e) {
                OAuth2Utils.DEBUG.error("ValidationServerResource::Error occurred during token verify", e);
                throw OAuthProblemException.OAuthError.ACCESS_DENIED.handle(null, e.getMessage());
            }
        } finally {
            if (response != null) {
                try {
                    response.getEntity().exhaust();
                } catch (IOException e) {
                    OAuth2Utils.DEBUG.error("ValidationServerResource::Error occurred while exhausting the content of the response", e);
                }
            }
            if (client != null) {
                try {
                    client.stop();
                } catch (Exception e) {
                    OAuth2Utils.DEBUG.error("ValidationServerResource::Error occurred whilst trying to stop" +
                            " Restlet client", e);
                }
            }
        }
    }

    private String getPluginClass(String realm) throws OAuthProblemException {
        String pluginClass = null;
        try {
            SSOToken token = (SSOToken) AccessController.doPrivileged(AdminTokenAction.getInstance());
            ServiceConfigManager mgr = new ServiceConfigManager(token, OAuth2Constants.OAuth2ProviderService.NAME, OAuth2Constants.OAuth2ProviderService.VERSION);
            ServiceConfig scm = mgr.getOrganizationConfig(realm, null);
            Map<String, Set<String>> attrs = scm.getAttributes();
            pluginClass = attrs.get(OAuth2Constants.OAuth2ProviderService.SCOPE_PLUGIN_CLASS).iterator().next();
        } catch (Exception e) {
            OAuth2Utils.DEBUG.error("ValidationServerResource::Unable to get plugin class", e);
            throw new OAuthProblemException(Status.SERVER_ERROR_SERVICE_UNAVAILABLE.getCode(),
                    "Service unavailable", "Could not create underlying storage", null);
        }

        return pluginClass;
    }

}
