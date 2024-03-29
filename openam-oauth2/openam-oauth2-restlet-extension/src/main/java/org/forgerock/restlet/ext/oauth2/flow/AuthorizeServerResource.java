/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions Copyrighted [year] [name of copyright owner]".
 *
 * Copyright 2012-2014 ForgeRock AS. All rights reserved.
 */

package org.forgerock.restlet.ext.oauth2.flow;


import com.iplanet.am.util.SystemProperties;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.shared.OAuth2Constants;
import com.sun.identity.shared.encode.Base64;

import java.util.ArrayList;
import java.util.Arrays;

import org.apache.commons.lang.StringUtils;
import org.forgerock.openam.oauth2.exceptions.OAuthProblemException;
import org.forgerock.openam.oauth2.model.ClientApplication;
import org.forgerock.openam.oauth2.model.CoreToken;
import org.forgerock.openam.oauth2.model.impl.ClientApplicationImpl;
import org.forgerock.openam.oauth2.openid.OpenIDPromptParameter;
import org.forgerock.openam.oauth2.provider.OAuth2ProviderSettings;
import org.forgerock.openam.oauth2.provider.ResponseType;
import org.forgerock.openam.oauth2.utils.OAuth2Utils;
import org.restlet.data.Form;
import org.restlet.data.Parameter;
import org.restlet.data.Reference;
import org.restlet.ext.json.JsonRepresentation;
import org.restlet.representation.Representation;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.routing.Redirector;

import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.nio.charset.Charset;
import java.security.MessageDigest;

public class AuthorizeServerResource extends AbstractFlow {

    /**
     * Developers should note that some user-agents do not support the inclusion
     * of a fragment component in the HTTP "Location" response header field.
     * Such clients will require using other methods for redirecting the client
     * than a 3xx redirection response. For example, returning an HTML page
     * which includes a 'continue' button with an action linked to the
     * redirection URI.
     * <p/>
     * If TLS is not available, the authorization server SHOULD warn the
     * resource owner about the insecure endpoint prior to redirection.
     *
     * @return
     */
    @Get("html")
    public Representation represent() {

        // Validate the client
        client = validateRemoteClient();
        // Validate Redirect URI throw exception
        sessionClient =
                client.getClientInstance(OAuth2Utils.getRequestParameter(getRequest(),
                        OAuth2Constants.Params.REDIRECT_URI, String.class));

        // The target contains the state
        String state =
                OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Params.STATE, String.class);

        // Get the requested scope
        String scope_before =
                OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Params.SCOPE, String.class);

        // Validate the granted scope
        Set<String> checkedScope = executeAuthorizationPageScopePlugin(scope_before);

        String prompt =
                OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Custom.PROMPT, String.class);

        if (StringUtils.isBlank(prompt)){
            prompt = OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Custom._PROMPT, String.class);
        }

        OpenIDPromptParameter openIDPromptParameter = new OpenIDPromptParameter(prompt);
        if (!openIDPromptParameter.isValid()){
            throw OAuthProblemException.OAuthError.BAD_REQUEST.handle(getRequest(), "Prompt parameter is invalid");
        }

        //check if there is an invalid response type
        String responseType =
                OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Params.RESPONSE_TYPE, String.class);
        if (responseType != null && !responseType.isEmpty()) {
            if (!validResponseTypes(OAuth2Utils.stringToSet(responseType))) {
                OAuth2Utils.DEBUG.warning("AuthorizeServerResource.represent(): Requested a response type that is not configured.");
                throw OAuthProblemException.OAuthError.UNSUPPORTED_RESPONSE_TYPE.handle(getRequest(), "Response type is not supported");
            }
        } else {
            OAuth2Utils.DEBUG.warning("AuthorizeServerResource.represent(): Requested a response type that is not configured.");
            throw OAuthProblemException.OAuthError.UNSUPPORTED_RESPONSE_TYPE.handle(getRequest(), "Response type is not supported");
        }

        //authenticate the resource owner
        resourceOwner = getAuthenticatedResourceOwner();

        //check for saved consent
        boolean savedConsent = savedConsent(resourceOwner.getIdentifier(), sessionClient.getClientId(), checkedScope);

        if (openIDPromptParameter.noPrompts() && !savedConsent){
            throw OAuthProblemException.OAuthError.CONSENT_REQUIRED.handle(getRequest());
        } else if (!openIDPromptParameter.promptConsent() && openIDPromptParameter.promptLogin() && !savedConsent) {
            throw OAuthProblemException.OAuthError.CONSENT_REQUIRED.handle(getRequest());
        } else if (savedConsent && !openIDPromptParameter.promptConsent()) {
            Map<String, Object> attrs = getRequest().getAttributes();
            attrs.put(OAuth2Constants.Custom.DECISION, OAuth2Constants.Custom.ALLOW);
            // 2018.02.19 add CSRF脆弱性対策によるSavedConsent不具合対応
            SSOToken ssoToken = OAuth2Utils.getSSOToken(getRequest());
            attrs.put(OAuth2Constants.Custom.CSRF, ssoToken.getTokenID().toString());
            // 2018.02.19 add -- end
            getRequest().setAttributes(attrs);
            Representation rep = new JsonRepresentation(new HashMap());
            return represent(rep);
        } else if (!savedConsent || openIDPromptParameter.promptConsent()) {
            return getPage("authorize.ftl", getDataModel(checkedScope));
        }
        return getPage("authorize.ftl", getDataModel(checkedScope));
    }

    @Post("form:json")
    public Representation represent(Representation entity) {

         // 2018.02.19 add OPENAM-8575 OAuth2.0認証画面 CSRF脆弱性対策 --- sta
        Charset UTF_8_CHARSET = Charset.forName("UTF-8");
        SSOToken ssoToken = OAuth2Utils.getSSOToken(getRequest());
        String csrfValue = OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Custom.CSRF, String.class);
        if ( csrfValue == null ||
                (ssoToken != null &&  !MessageDigest.isEqual(ssoToken.getTokenID().toString().getBytes(UTF_8_CHARSET), csrfValue.getBytes(UTF_8_CHARSET)) )) {
            OAuth2Utils.DEBUG.error("Session id from consent request does not match users session");
            throw OAuthProblemException.OAuthError.BAD_REQUEST.handle(getRequest(), "bad_request");
        }
        // 2018.02.19 add -- end

        resourceOwner = getAuthenticatedResourceOwner();
        client = validateRemoteClient();
        sessionClient =
                client.getClientInstance(OAuth2Utils.getRequestParameter(getRequest(),
                        OAuth2Constants.Params.REDIRECT_URI, String.class));

        String decision = OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Custom.DECISION,
                String.class);

        if (OAuth2Constants.Custom.ALLOW.equalsIgnoreCase(decision)) {
            String save_consent =
                    OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Custom.SAVE_CONSENT, String.class);

            String scope_after =
                    OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Params.SCOPE, String.class);

            if (save_consent != null && save_consent.equalsIgnoreCase("on")) {
                saveConsent(resourceOwner.getIdentifier(), sessionClient.getClientId(), scope_after);
            }

            String state =
                    OAuth2Utils
                            .getRequestParameter(getRequest(), OAuth2Constants.Params.STATE, String.class);
            String nonce =
                    OAuth2Utils
                            .getRequestParameter(getRequest(), OAuth2Constants.Custom.NONCE, String.class);

            Set<String> checkedScope = executeAccessTokenScopePlugin(scope_after);


            Map<String, String> responseTypes = null;
            responseTypes = getResponseTypes(OAuth2Utils.getRealm(getRequest()));

            Set<String> tmpRequestedResponseTypes = OAuth2Utils.stringToSet(OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Params.RESPONSE_TYPE, String.class));
            Map<String, CoreToken> listOfTokens = new HashMap<String, CoreToken>();
            Map<String, Object> data = new HashMap<String, Object>();
            data.put(OAuth2Constants.CoreTokenParams.TOKEN_TYPE, client.getClient().getAccessTokenType());
            data.put(OAuth2Constants.CoreTokenParams.SCOPE, checkedScope);
            data.put(OAuth2Constants.CoreTokenParams.REALM, OAuth2Utils.getRealm(getRequest()));
            data.put(OAuth2Constants.CoreTokenParams.USERNAME, resourceOwner.getIdentifier());
            data.put(OAuth2Constants.CoreTokenParams.CLIENT_ID, sessionClient.getClientId());
            data.put(OAuth2Constants.CoreTokenParams.REDIRECT_URI, sessionClient.getRedirectUri());
            data.put(OAuth2Constants.Custom.NONCE, nonce);
            data.put(OAuth2Constants.Custom.SSO_TOKEN_ID, getRequest().getCookies().getValues(
                    SystemProperties.get("com.iplanet.am.cookie.name")));

            if (tmpRequestedResponseTypes == null || tmpRequestedResponseTypes.isEmpty()) {
                OAuth2Utils.DEBUG.error("AuthorizeServerResource.represent(): Error response_type not set");
                throw OAuthProblemException.OAuthError.UNSUPPORTED_RESPONSE_TYPE.handle(getRequest(),
                        "Response type is not supported");
            }

            List<String> requestedResponseTypes = new ArrayList<String>(tmpRequestedResponseTypes);
            if (requestedResponseTypes.contains("id_token") && nonce == null) {
                OAuth2Utils.DEBUG.error("AuthorizeServerResource.represent(): Missing required parameter nonce from request");
                throw OAuthProblemException.OAuthError.INVALID_REQUEST.handle(getRequest(),
                        "Missing required parameter nonce from request");
            }

            // at_hash, c_hashを先に生成する必要があるため、id_tokenを最後に処理する。
            if (requestedResponseTypes.contains("id_token")) {
                requestedResponseTypes.remove("id_token");
                requestedResponseTypes.add("id_token");
            }

            AMIdentity id = OAuth2Utils.getClientIdentity(sessionClient.getClientId(), OAuth2Utils.getRealm(getRequest()));
            ClientApplication clientApplication = new ClientApplicationImpl(id);
            String algorithm = clientApplication.getIDTokenSignedResponseAlgorithm();

            String atHash = null;
            String cHash = null;
            try {
                for (String request : requestedResponseTypes) {
                    if (request.isEmpty()) {
                        throw OAuthProblemException.OAuthError.UNSUPPORTED_RESPONSE_TYPE.handle(getRequest(),
                                "Response type is not supported");
                    }
                    if (request.equals("id_token")) {
                        if (atHash != null && !atHash.isEmpty()) {
                            data.put(OAuth2Constants.JWTTokenParams.AT_HASH, urlEnc(atHash));
                        }
                        if (cHash != null && !cHash.isEmpty()) {
                            data.put(OAuth2Constants.JWTTokenParams.C_HASH, urlEnc(cHash));
                        }
                    }
                    String responseClass = responseTypes.get(request);
                    if (responseClass == null || responseClass.isEmpty()) {
                        OAuth2Utils.DEBUG.warning("AuthorizeServerResource.represent(): Requested a response type that is not configured. response_type=" + request);
                        throw OAuthProblemException.OAuthError.UNSUPPORTED_RESPONSE_TYPE.handle(getRequest(),
                                "Response type is not supported");
                    } else if (responseClass.equalsIgnoreCase("none")) {
                        continue;
                    }
                    //execute response type class
                    Class clazz = Class.forName(responseClass);
                    ResponseType classObj = (ResponseType) clazz.newInstance();

                    //create the response type token
                    CoreToken token = classObj.createToken(data);

                    //get the response type return location
                    String paramName = classObj.URIParamValue();
                    if (listOfTokens.containsKey(paramName)) {
                        OAuth2Utils.DEBUG.error("AuthorizeServerResource.represent(): Returning multiple response types with the same url value");
                        throw OAuthProblemException.OAuthError.UNSUPPORTED_RESPONSE_TYPE.handle(getRequest(),
                                "Returning multiple response types with the same url value");
                    }
                    listOfTokens.put(classObj.URIParamValue(), token);

                    if (request.equals("token")) {
                        atHash = hash(token.getTokenID(), getAlgorithm(algorithm));
                    } else if (request.equals("code")) {
                        cHash = hash(token.getTokenID(), getAlgorithm(algorithm));
                    }

                    //if return location is fragment all tokens need to be returned as a fragment
                    if (fragment == false) {
                        String location = classObj.getReturnLocation();
                        if (location.equalsIgnoreCase("FRAGMENT")) {
                            fragment = true;
                        }
                    }
                }
            } catch (Exception e) {
                OAuth2Utils.DEBUG.error("AuthorizeServerResource.represent(): Error invoking classes for response_type", e);
                throw OAuthProblemException.OAuthError.UNSUPPORTED_RESPONSE_TYPE.handle(getRequest(),
                        "Response type is not supported");
            }

            Form tokenForm = tokensToForm(listOfTokens);

            //execute post token creation pre return scope plugin for extra return data.
            Map<String, String> extraData = new HashMap<String, String>();

            Map<String, String> valuesToAdd = executeAuthorizationExtraDataScopePlugin(extraData, listOfTokens);

            if (valuesToAdd != null && !valuesToAdd.isEmpty()) {
                String returnType = valuesToAdd.remove("returnType");
                if (returnType != null && !returnType.isEmpty()) {
                    if (returnType.equalsIgnoreCase("FRAGMENT")) {
                        fragment = true;
                    }
                }
            }
            for (Map.Entry<String, String> entry : valuesToAdd.entrySet()) {
                tokenForm.add(entry.getKey(), entry.getValue().toString());
            }

            /*
             * scope OPTIONAL, if identical to the scope requested by the
             * client, otherwise REQUIRED. The scope of the access token as
             * described by Section 3.3.
             */
            if (isScopeChanged()) {
                String scope_before =
                        OAuth2Utils.getRequestParameter(getRequest(), OAuth2Constants.Params.SCOPE, String.class);

                checkedScope = executeAccessTokenScopePlugin(scope_before);
                if (checkedScope != null && !checkedScope.isEmpty()) {
                    tokenForm.add(OAuth2Constants.Params.SCOPE, OAuth2Utils.join(checkedScope, OAuth2Utils
                            .getScopeDelimiter(getContext())));
                }

            }
            if (null != state) {
                tokenForm.add(OAuth2Constants.Params.STATE, state);
            }

            Reference redirectReference = new Reference(sessionClient.getRedirectUri());

            if (fragment) {
                redirectReference.setFragment(tokenForm.getQueryString());
            } else {
                Iterator<Parameter> iter = tokenForm.iterator();
                while (iter.hasNext()) {
                    redirectReference.addQueryParameter(iter.next());
                }
            }

            Redirector dispatcher =
                    new Redirector(getContext(), redirectReference.toString(),
                            Redirector.MODE_CLIENT_FOUND);
            dispatcher.handle(getRequest(), getResponse());
        } else {
            OAuth2Utils.DEBUG.warning("AuthorizeServerResource::Resource Owner did not authorize the request");
            throw OAuthProblemException.OAuthError.ACCESS_DENIED.handle(getRequest(),
                    "Resource Owner did not authorize the request");
        }
        return getResponseEntity();
    }

    @Override
    protected String[] getRequiredParameters() {
        return new String[]{OAuth2Constants.Params.RESPONSE_TYPE, OAuth2Constants.Params.CLIENT_ID};
    }

    protected Form tokensToForm(Map<String, CoreToken> tokens) {

        Form result = new Form();
        for (Map.Entry<String, CoreToken> entry : tokens.entrySet()) {
            Map<String, Object> token = entry.getValue().convertToMap();
            Parameter p = new Parameter(entry.getKey(), entry.getValue().getTokenID());
            if (!result.contains(p)) {
                result.add(p);
            }
            //if access token add extra fields
            if (entry.getValue().getTokenName().equalsIgnoreCase(OAuth2Constants.Params.ACCESS_TOKEN)) {
                for (Map.Entry<String, Object> entryInMap : token.entrySet()) {
                    p = new Parameter(entryInMap.getKey(), entryInMap.getValue().toString());
                    if (!result.contains(p)) {
                        result.add(p);
                    }
                }
            }

        }
        return result;
    }

    protected boolean savedConsent(String userid, String clientId, Set<String> scopes) {
        OAuth2ProviderSettings settings = OAuth2Utils.getSettingsProvider(getRequest());
        // 2018.02.09 upd --sta
        // SharedConsentAttributeNameが null の場合、エラーメッセージを出力する
        String attribute = settings.getSharedConsentAttributeName();
        if (attribute != null) {
            AMIdentity id = OAuth2Utils.getIdentity(userid, OAuth2Utils.getRealm(getRequest()));
            Set<String> attributeSet = null;

            if (id != null) {
                try {
                    attributeSet = id.getAttribute(attribute);
                } catch (Exception e) {
                    OAuth2Utils.DEBUG.error("AuthorizeServerResource.saveConsent(): Unable to get profile attribute", e);
                    return false;
                }
            }

            // check the values of the attribute set vs the scope and client requested
            // attribute set is in the form of client_id|scope1 scope2 scope3
            for (String attr : attributeSet) {
                String[] consents = attr.split("\\|");
                for (String consent : consents) {
                    int loc = consent.indexOf(" ");
                    String consentClientId = consent.substring(0, loc);
                    String[] scopesArray = null;
                    if (loc + 1 < consent.length()) {
                        scopesArray = consent.substring(loc + 1, consent.length()).split(" ");
                    }
                    Set<String> consentScopes = null;
                    if (scopesArray != null && scopesArray.length > 0) {
                        consentScopes = new HashSet<String>(Arrays.asList(scopesArray));
                    } else {
                        consentScopes = new HashSet<String>();
                    }

                    //if both the client and the scopes are identical to the saved consent then approve
                    if (clientId.equals(consentClientId) && scopes.equals(consentScopes)) {
                        return true;
                    }
                }
            }
        } else {
            OAuth2Utils.DEBUG.error("No saved consent attribute defined in realm:" + OAuth2Utils.getRealm(getRequest()));
        }
     // 2018.02.09 upd --end

        return false;
    }

    protected void saveConsent(String userId, String clientId, String scopes) {
        AMIdentity id = OAuth2Utils.getIdentity(userId, OAuth2Utils.getRealm(getRequest()));
        OAuth2ProviderSettings settings = OAuth2Utils.getSettingsProvider(getRequest());
        String consentAttribute = settings.getSharedConsentAttributeName();
        // 2018.02.09 upd --sta
        // SharedConsentAttributeNameが null の場合、エラーメッセージを出力する
        if (consentAttribute != null) {

            try {
                //get the current set of consents and add our new consent to it.
                Set<String> consents = new HashSet<String>(id.getAttribute(consentAttribute));
                StringBuilder sb = new StringBuilder();
                if (scopes == null || scopes.isEmpty()) {
                    sb.append(clientId.trim()).append(" ");
                } else {
                    sb.append(clientId.trim()).append(" ").append(scopes.trim());
                }

                Set<String> newConsents = new HashSet<String>();
                StringBuilder contentSb = new StringBuilder();
                for (String consent : consents) {
                    String[] attrs = consent.split("\\|");
                    for (String attr : attrs) {
                        int loc = attr.indexOf(" ");
                        String attrClientId = attr.substring(0, loc);
                        if (!clientId.equals(attrClientId)) {
                            contentSb.append(attr).append("|");
                        }
                    }
                }
                contentSb.append(sb.toString());
                newConsents.add(contentSb.toString());

                //update the user profile with our new consent settings
                Map<String, Set<String>> attrs = new HashMap<String, Set<String>>();
                attrs.put(consentAttribute, newConsents);
                id.setAttributes(attrs);
                id.store();
            } catch (Exception e) {
                OAuth2Utils.DEBUG.error("AuthorizeServerResource.saveConsent(): Unable to save consent ", e);
            }
        } else {
            OAuth2Utils.DEBUG.error("No saved consent attribute defined in realm:" + OAuth2Utils.getRealm(getRequest()));
        }
        // 2018.02.09 upd --end
    }

    private boolean validResponseTypes(Set<String> responseTypesRequested) {

        Map<String, String> allResponseTypes = getResponseTypes(OAuth2Utils.getRealm(getRequest()));
        return allResponseTypes.keySet().containsAll(responseTypesRequested);
    }

    private String getAlgorithm(String algorithm) {
        if (algorithm.equals("HS256")) {
            return "SHA-256";
        } else if (algorithm.equals("HS384")) {
            return "SHA-384";
        } else if (algorithm.equals("HS512")) {
            return "SHA-512";
        } else if (algorithm.equals("RS256")) {
            return "SHA-256";
        } else {
            return "SHA-1";
        }
    }

    private String hash(String string, String algorithm) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance(algorithm);
            sha1.update(string.getBytes("UTF-8"));
            byte[] result = sha1.digest();
            final byte[] toEncode = Arrays.copyOfRange(result, 0, result.length / 2);
            return Base64.encode(toEncode);
        } catch (Exception ex) {
            OAuth2Utils.DEBUG.warning("AuthorizeServerResource.hash(): ", ex);
            return null;
        }
    }

    private String urlEnc(String value) {
        String result = value;
        result = result.replaceAll("\\+", "-");
        result = result.replaceAll("/", "_");
        result = result.replaceAll("=", "");
        return result;
    }

}
