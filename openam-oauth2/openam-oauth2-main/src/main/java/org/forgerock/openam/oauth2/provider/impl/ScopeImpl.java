/*
 * DO NOT REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2012-2013 ForgeRock AS All rights reserved.
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

package org.forgerock.openam.oauth2.provider.impl;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.*;
import com.sun.identity.shared.OAuth2Constants;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.JwsAlgorithmType;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openam.ext.cts.repo.DefaultOAuthTokenStoreImpl;
import org.forgerock.openam.oauth2.exceptions.OAuthProblemException;
import org.forgerock.openam.guice.InjectorHolder;
import org.forgerock.openam.oauth2.model.CoreToken;
import org.forgerock.openam.oauth2.model.CustomSignedJwt;
import org.forgerock.openam.oauth2.model.JWTToken;
import org.forgerock.openam.oauth2.model.CustomSigningManager;
import org.forgerock.openam.oauth2.model.handlers.CustomSigningHandler;
import org.forgerock.openam.oauth2.provider.OAuth2TokenStore;
import org.forgerock.openam.oauth2.provider.Scope;
import org.forgerock.openam.oauth2.utils.OAuth2Utils;
import org.restlet.Request;
import org.forgerock.util.encode.Base64url;
import org.forgerock.json.jose.utils.Utils;
import org.forgerock.json.jose.jwt.JwtHeader;

import java.security.SignatureException;
import java.util.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.lang.reflect.Method;
import java.lang.reflect.Field;

/**
 * This is the default scope implementation class. This class by default
 * follows the OAuth2 specs rules regarding how scope should be assigned.
 * The only exceptions is in the retrieveTokenInfoEndPoint method end point
 * the scopes are assumed to be OpenAM user attributes, which will be returned
 * upon the completion of the retrieveTokenInfoEndPoint method
 */
public class ScopeImpl implements Scope {
    private static final String MULTI_ATTRIBUTE_SEPARATOR = ",";
    private static final String OPENID_SCOPE = "openid";
    private static final String EMAIL_SCOPE = "email";
    private static final String ADDRESS_SCOPE = "address";
    private static final String PHONE_SCOPE = "phone";
    private static final String NAME_SCOPE = "name";
    private static final String GIVEN_NAME_SCOPE = "given_name";
    private static final String FAMILY_NAME_SCOPE = "family_name";
    private static final String LOCALE_SCOPE = "locale";
    private static final String ZONEINFO_SCOPE = "zoneinfo";
    private static final String PROFILE_SCOPE = "profile";

    private static Map<String, Object> scopeToUserUserProfileAttributes;

    static {
        scopeToUserUserProfileAttributes = new HashMap<String, Object>();
        scopeToUserUserProfileAttributes.put(EMAIL_SCOPE,"mail");
        scopeToUserUserProfileAttributes.put(ADDRESS_SCOPE, "postaladdress");
        scopeToUserUserProfileAttributes.put(PHONE_SCOPE, "telephonenumber");

        Map<String, Object> profileSet = new HashMap<String, Object>();
        profileSet.put(NAME_SCOPE, "cn");
        profileSet.put(GIVEN_NAME_SCOPE, "givenname");
        profileSet.put(FAMILY_NAME_SCOPE, "sn");
        profileSet.put(LOCALE_SCOPE, "preferredlocale");
        profileSet.put(ZONEINFO_SCOPE, "preferredtimezone");

        scopeToUserUserProfileAttributes.put(PROFILE_SCOPE, profileSet);
    }

    private OAuth2TokenStore store = null;
    private AMIdentity id = null;

    public ScopeImpl(){
        this.store = InjectorHolder.getInstance(DefaultOAuthTokenStoreImpl.class);
        this.id = null;
    }

    public ScopeImpl(OAuth2TokenStore store, AMIdentity id){
        this.store = store;
        this.id = id;
    }

    /**
     * {@inheritDoc}
     */
    public Set<String> scopeToPresentOnAuthorizationPage(Set<String> requestedScope, Set<String> availableScopes, Set<String> defaultScopes){

        if (requestedScope == null || requestedScope.isEmpty()) {
            return defaultScopes;
        }

        Set<String> scopes = new HashSet<String>(availableScopes);
        scopes.retainAll(requestedScope);
        return scopes;
    }

    /**
     * {@inheritDoc}
     */
    public Set<String> scopeRequestedForAccessToken(Set<String> requestedScope, Set<String> availableScopes, Set<String> defaultScopes){

        if (requestedScope == null || requestedScope.isEmpty()) {
            return defaultScopes;
        }

        Set<String> scopes = new HashSet<String>(availableScopes);
        scopes.retainAll(requestedScope);
        return scopes;
    }

    /**
     * {@inheritDoc}
     */
    public Set<String> scopeRequestedForRefreshToken(Set<String> requestedScope,
                                                     Set<String> availableScopes,
                                                     Set<String> allScopes,
                                                     Set<String> defaultScopes){

        if (requestedScope == null || requestedScope.isEmpty()) {
            return availableScopes;
        }

        Set<String> scopes = new HashSet<String>(availableScopes);
        scopes.retainAll(requestedScope);
        return scopes;
    }

    /**
     * {@inheritDoc}
     */
    public Map<String, Object> evaluateScope(CoreToken token){
        Map<String, Object> map = new HashMap<String, Object>();
        Set<String> scopes = token.getScope();
        String resourceOwner = token.getUserID();

        if ((resourceOwner != null) && (scopes != null) && (!scopes.isEmpty())){
            AMIdentity id = null;
            try {

                if (this.id == null){
                    id = OAuth2Utils.getIdentity(resourceOwner, token.getRealm());
                } else {
                    id = this.id;
                }
            } catch (Exception e){
                OAuth2Utils.DEBUG.error("Unable to get user identity", e);
            }
            if (id != null){
                for (String scope : scopes){
                    try {
                        Set<String> attributes = id.getAttribute(scope);
                        if (attributes != null && !attributes.isEmpty()) {
                            Iterator<String> iter = attributes.iterator();
                            StringBuilder builder = new StringBuilder();
                            while (iter.hasNext()) {
                                builder.append(iter.next());
                                if (iter.hasNext()) {
                                    builder.append(MULTI_ATTRIBUTE_SEPARATOR);
                                }
                            }
                            map.put(scope, builder.toString());
                        }
                    } catch (Exception e){
                        OAuth2Utils.DEBUG.error("Unable to get attribute", e);
                    }
                }
            }
        }

        return map;
    }

    /**
     * {@inheritDoc}
     */
    public Map<String, Object> extraDataToReturnForTokenEndpoint(Map<String, String> parameters, CoreToken token){
        Map<String, Object> map = new HashMap<String, Object>();
        Set<String> scope = token.getScope();

        //OpenID Connect
        // if an openid scope return the id_token
        if (scope != null && scope.contains(OPENID_SCOPE)){
            DefaultOAuthTokenStoreImpl store = InjectorHolder.getInstance(DefaultOAuthTokenStoreImpl.class);
            CoreToken jwtToken = store.createJWT(token.getRealm(),
                    token.getUserID(),
                    token.getClientID(),
                    token.getClientID(),
                    parameters.get(OAuth2Constants.Custom.NONCE),
                    parameters.get(OAuth2Constants.Custom.SSO_TOKEN_ID));

            String clientSecret = null;
            try {
                clientSecret = parameters.get("clientSecret");
            } catch (Exception e) {
                OAuth2Utils.DEBUG.error("ScopeImpl.extraDataToReturnForTokenEndpoint()::Unable to sign JWT", e);
                throw OAuthProblemException.OAuthError.SERVER_ERROR.handle(Request.getCurrent(), "Cant sign JWT");
            }

            CustomSignedJwt signedJwt = null;
            try {
                signedJwt =((JWTToken) jwtToken).sign(OAuth2Utils.getServerKeyPair(Request.getCurrent()).getPrivate(), clientSecret);
            } catch (SignatureException e){
                OAuth2Utils.DEBUG.error("ScopeImpl.extraDataToReturnForTokenEndpoint()::Unable to sign JWT", e);
                throw OAuthProblemException.OAuthError.SERVER_ERROR.handle(Request.getCurrent(),
                        "Cant sign JWT");
            }

            // update at 2018.02.02 header algorithm "none" --- sta
            String headerAlgorithm = null;
            try {
                Class<JwtHeader> c = JwtHeader.class;
                Method method = c.getDeclaredMethod( "getAlgorithmString" );
                method.setAccessible( true );
                headerAlgorithm = (String)method.invoke( signedJwt.getHeader());
            } catch (Exception e) {
                OAuth2Utils.DEBUG.error("ScopeImpl.extraDataToReturnForTokenEndpoint()::Unable to sign JWT", e);
                throw OAuthProblemException.OAuthError.SERVER_ERROR.handle(Request.getCurrent(), "Cant sign JWT");
            }

            // update at 2018.02.20 algorithm type "HS256,HS384,HS512"
//            if ("none".equals(headerAlgorithm)) {
            String jwsPayload = null;
            try  {
                Field fieldPayload = null;
                fieldPayload = CustomSignedJwt.class.getDeclaredField("payload");
                fieldPayload.setAccessible(true);
                jwsPayload =  fieldPayload.get(signedJwt).toString();
            } catch (Exception e) {
                OAuth2Utils.DEBUG.error("ScopeImpl.extraDataToReturnForTokenEndpoint()::Unable to sign JWT", e);
                throw OAuthProblemException.OAuthError.SERVER_ERROR.handle(Request.getCurrent(), "Cant sign JWT");
            }

            String jwsHeader = signedJwt.getHeader().build();
            String encodedHeader = Utils.base64urlEncode(jwsHeader);
            String encodedClaims = Utils.base64urlEncode(jwsPayload);
            String signingInput = encodedHeader + "." + encodedClaims;
            String id_token = signingInput + ".";

            if (!"none".equals(headerAlgorithm)) {
                CustomSigningManager signingManager = new CustomSigningManager();
                CustomSigningHandler signingHandler = signingManager.getSigningHandler(signedJwt.getHeader().getAlgorithm());
                byte[] signature = null;
                if (JwsAlgorithmType.RSA.equals(signedJwt.getHeader().getAlgorithm().getAlgorithmType())) {
                    signature = signingHandler.sign(signedJwt.getHeader().getAlgorithm(), OAuth2Utils.getServerKeyPair(Request.getCurrent()).getPrivate(), signingInput);
                } else {
                    signature = signingHandler.sign(signedJwt.getHeader().getAlgorithm(), clientSecret, signingInput);
                }
                id_token = id_token + Base64url.encode(signature);
            }

            map.put("id_token", id_token);
//            } else {
//                map.put("id_token", signedJwt.build());
//            }
            // update at 2018.02.20 algorithm type "HS256,HS384,HS512"
            // update at 2018.02.02 --- end

        }
        //END OpenID Connect
        return map;
    }

    /**
     * {@inheritDoc}
     */
    public Map<String, String> extraDataToReturnForAuthorizeEndpoint(Map<String, String> parameters, Map<String, CoreToken> tokens){
        Map<String, String> map = new HashMap<String, String>();
        return map;
    }

    /**
     * {@inheritDoc}
     */
    public Map<String,Object> getUserInfo(CoreToken token){

        Set<String> scopes = token.getScope();
        Map<String,Object> response = new HashMap<String, Object>();
        AMIdentity id = null;
        if (this.id == null){
            id = OAuth2Utils.getIdentity(token.getUserID(), token.getRealm());
        } else {
            id = this.id;
        }

        // add the subject identifier to the response
        response.put("sub", token.getUserID());
        for(String scope: scopes){
            if (scope.equals(OPENID_SCOPE)) {
                continue;
            }

            // get the attribute associated with the scope
            Object attributes = scopeToUserUserProfileAttributes.get(scope);
            if (attributes == null){
             OAuth2Utils.DEBUG.error("ScopeImpl.getUserInfo()::Invalid Scope in token scope="+ scope);
            } else if (attributes instanceof String){
                Set<String> attr = null;

                // if the attribute is a string get the attribute
                try {
                    attr = id.getAttribute((String)attributes);
                } catch (IdRepoException e) {
                    OAuth2Utils.DEBUG.error("ScopeImpl.getUserInfo(): Unable to retrieve atrribute", e);
                } catch (SSOException e) {
                    OAuth2Utils.DEBUG.error("ScopeImpl.getUserInfo(): Unable to retrieve atrribute", e);
                }

                // add a single object to the response.
                if (scope.equals(ADDRESS_SCOPE)) {
                    Map<String,Object> addressAttr = transAddress(attr);
                    if (addressAttr == null || addressAttr.isEmpty()) {
                        OAuth2Utils.DEBUG.error("ScopeImpl.getUserInfo(): Got an empty result for scope=" + scope);
                    } else {
                        response.put(scope, addressAttr);
                    }
                } else if (attr != null && attr.size() == 1){
                    response.put(scope, attr.iterator().next());
                } else if (attr != null && attr.size() > 1){ // add a set to the response
                    response.put(scope, attr);
                } else {
                    //attr is null or attr is empty
                    OAuth2Utils.DEBUG.error("ScopeImpl.getUserInfo(): Got an empty result for scope=" + scope);
                }
            } else if (attributes instanceof Map){

                // the attribute is a collection of attributes
                // for example profile can be address, email, etc...
                if (attributes != null && !((Map<String,String>) attributes).isEmpty()){
                    for (Map.Entry<String, String> entry: ((Map<String, String>) attributes).entrySet()){
                        String attribute = null;
                        attribute = (String)entry.getValue();
                        Set<String> attr = null;

                        // get the attribute
                        try {
                            attr = id.getAttribute(attribute);
                        } catch (IdRepoException e) {
                            OAuth2Utils.DEBUG.error("ScopeImpl.getUserInfo(): Unable to retrieve atrribute", e);
                        } catch (SSOException e) {
                            OAuth2Utils.DEBUG.error("ScopeImpl.getUserInfo(): Unable to retrieve atrribute", e);
                        }

                        // add the attribute value(s) to the response
                        if (attr != null && attr.size() == 1){
                            response.put(entry.getKey(), attr.iterator().next());
                        } else if (attr != null && attr.size() > 1){
                            response.put(entry.getKey(), attr);
                        } else {
                            // attr is null or attr is empty
                            OAuth2Utils.DEBUG.error("ScopeImpl.getUserInfo(): Got an empty result for scope=" + scope);
                        }
                    }
                }
            }
        }

        return response;
    }

    private Map<String,Object> transAddress(Set<String> attr) {
        if (attr == null || attr.size() == 0){
            return null;
        }

        Map<String,Object> map = new HashMap<String,Object>();
        final String key = "formatted";
        if (attr.size() == 1){
            map.put(key, attr.iterator().next());
        } else {
            Iterator<String> it = attr.iterator();
            for (int i = 0; it.hasNext(); i++) {
                map.put(key + "_" + i, it.next());
            }
        }

        return map;
    }

}
