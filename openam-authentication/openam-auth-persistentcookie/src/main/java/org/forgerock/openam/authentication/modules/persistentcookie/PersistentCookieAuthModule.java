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
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2013-2015 ForgeRock AS.
 */

package org.forgerock.openam.authentication.modules.persistentcookie;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.LoginException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.AccessController;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.AuthenticationException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;
import org.apache.commons.lang.StringUtils;
import org.forgerock.jaspi.filter.AuthNFilter;
import org.forgerock.jaspi.modules.session.jwt.JwtSessionModule;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.openam.authentication.modules.common.JaspiAuthModuleWrapper;
import org.forgerock.openam.utils.AMKeyProvider;

/**
 * Authentication logic for persistent cookie authentication in OpenAM. Making use of the JASPI JwtSessionModule
 * to create and verify the persistent cookie.
 *
 * @author Phill Cunnington phill.cunnington@forgerock.com
 */
public class PersistentCookieAuthModule extends JaspiAuthModuleWrapper<JwtSessionModule> {

    private static final String AUTH_RESOURCE_BUNDLE_NAME = "amAuthPersistentCookie";
    private static final Debug DEBUG = Debug.getInstance(AUTH_RESOURCE_BUNDLE_NAME);
    private static final String AUTH_SERVICE_NAME = "iPlanetAMAuthService";
    private static final String AUTH_KEY_ALIAS = "iplanet-am-auth-key-alias";
    private static final String SSO_TOKEN_ORGANIZATION_PROPERTY_KEY = "Organization";
    private static final int MINUTES_IN_HOUR = 60;

    private static final String COOKIE_IDLE_TIMEOUT_SETTING_KEY = "openam-auth-persistent-cookie-idle-time";
    private static final String COOKIE_MAX_LIFE_SETTING_KEY = "openam-auth-persistent-cookie-max-life";
    private static final String SECURE_COOKIE_KEY = "openam-auth-persistent-cookie-secure-cookie";
    private static final String HTTP_ONLY_COOKIE_KEY = "openam-auth-persistent-cookie-http-only-cookie";
    private static final String COOKIE_NAME_KEY = "openam-auth-persistent-cookie-name"; 

    private static final String OPENAM_USER_CLAIM_KEY = "openam.usr";
    private static final String OPENAM_AUTH_TYPE_CLAIM_KEY = "openam.aty";
    private static final String OPENAM_SESSION_ID_CLAIM_KEY = "openam.sid";
    private static final String OPENAM_REALM_CLAIM_KEY = "openam.rlm";

    private final AMKeyProvider amKeyProvider;
    private Integer tokenIdleTime;
    private Integer maxTokenLife;
    private boolean secureCookie;
    private boolean httpOnlyCookie;
    private String cookieName;

    private Principal principal;

    /**
     * Constructs an instance of the PersistentCookieAuthModule.
     *
     * Used by the PersistentCookie in a server deployment environment.
     */
    public PersistentCookieAuthModule() {
        this(new JwtSessionModule(), new AMKeyProvider());
    }

    /**
     * Constructs an instance of the PersistentCookieAuthModule.
     *
     * Used in a unit test environment.
     *
     * @param jwtSessionModule An instance of the JwtSessionModule.
     * @param amKeyProvider An instance of the AMKeyProvider.
     */
    public PersistentCookieAuthModule(JwtSessionModule jwtSessionModule, AMKeyProvider amKeyProvider) {
        super(jwtSessionModule, AUTH_RESOURCE_BUNDLE_NAME);
        this.amKeyProvider = amKeyProvider;
    }

    /**
     * Initialises the JwtSessionModule for use by the AM Login Module.
     *
     * @param subject {@inheritDoc}
     * @param sharedState {@inheritDoc}
     * @param options {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    protected Map<String, Object> initialize(Subject subject, Map sharedState, Map options) {

        String idleTimeString = CollectionHelper.getMapAttr(options, COOKIE_IDLE_TIMEOUT_SETTING_KEY);
        String maxLifeString = CollectionHelper.getMapAttr(options, COOKIE_MAX_LIFE_SETTING_KEY);
        if (StringUtils.isEmpty(idleTimeString)) {
            DEBUG.warning("Cookie Idle Timeout not set. Defaulting to 0");
            idleTimeString = "0";
        }
        if (StringUtils.isEmpty(maxLifeString)) {
            DEBUG.warning("Cookie Max Life not set. Defaulting to 0");
            maxLifeString = "0";
        }
        tokenIdleTime = Integer.parseInt(idleTimeString) * MINUTES_IN_HOUR;
        maxTokenLife = Integer.parseInt(maxLifeString) * MINUTES_IN_HOUR;
        secureCookie = CollectionHelper.getBooleanMapAttr(options, SECURE_COOKIE_KEY, true);
        httpOnlyCookie = CollectionHelper.getBooleanMapAttr(options, HTTP_ONLY_COOKIE_KEY, true);
        cookieName = CollectionHelper.getMapAttr(options, COOKIE_NAME_KEY);

        try {
            return initialize(tokenIdleTime.toString(), maxTokenLife.toString(), getRequestOrg(),
                    secureCookie, httpOnlyCookie, cookieName);
        } catch (SMSException e) {
            DEBUG.error("Error initialising Authentication Module", e);
            return null;
        } catch (SSOException e) {
            DEBUG.error("Error initialising Authentication Module", e);
            return null;
        }
    }

    /**
     * Creates a Map of configuration information required to configure the JwtSessionModule.
     *
     * @param tokenIdleTime The number of seconds the JWT can be not used for before becoming invalid.
     * @param maxTokenLife The number of seconds the JWT can be used for before becoming invalid.
     * @param realm The realm for the persistent cookie.
     * @param secureCookie {@code true} if the persistent cookie should be set as secure.
     * @param httpOnlyCookie {@code true} if the persistent cookie should be set as http only.
     * @return A Map containing the configuration information for the JWTSessionModule.
     * @throws SMSException If there is a problem getting the key alias.
     * @throws SSOException If there is a problem getting the key alias.
     */
     private Map<String, Object> initialize(final String tokenIdleTime, final String maxTokenLife, final String realm,
                                 boolean secureCookie, boolean httpOnlyCookie, String cookieName) throws SMSException, SSOException {
        Map<String, Object> config = new HashMap<String, Object>();
        config.put(JwtSessionModule.KEY_ALIAS_KEY, getKeyAlias(realm));
        config.put(JwtSessionModule.PRIVATE_KEY_PASSWORD_KEY, amKeyProvider.getPrivateKeyPass());
        config.put(JwtSessionModule.KEYSTORE_TYPE_KEY, amKeyProvider.getKeystoreType());
        config.put(JwtSessionModule.KEYSTORE_FILE_KEY, amKeyProvider.getKeystoreFilePath());
        config.put(JwtSessionModule.KEYSTORE_PASSWORD_KEY, new String(amKeyProvider.getKeystorePass()));
        config.put(JwtSessionModule.TOKEN_IDLE_TIME_CLAIM_KEY, tokenIdleTime);
        config.put(JwtSessionModule.MAX_TOKEN_LIFE_KEY, maxTokenLife);
        config.put(JwtSessionModule.SECURE_COOKIE_KEY, secureCookie);
        config.put(JwtSessionModule.HTTP_ONLY_COOKIE_KEY, httpOnlyCookie);
        config.put(JwtSessionModule.SESSION_COOKIE_NAME_KEY, cookieName);
        
        return config;
    }

    /**
     * Overridden as to call different method on underlying JASPI JwtSessionModule.
     *
     * @param callbacks {@inheritDoc}
     * @param state {@inheritDoc}
     * @return {@inheritDoc}
     * @throws LoginException {@inheritDoc}
     */
    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {
        switch (state) {
            case ISAuthConstants.LOGIN_START: {
                setUserSessionProperty(JwtSessionModule.TOKEN_IDLE_TIME_CLAIM_KEY, tokenIdleTime.toString());
                setUserSessionProperty(JwtSessionModule.MAX_TOKEN_LIFE_KEY, maxTokenLife.toString());
                setUserSessionProperty(SECURE_COOKIE_KEY, Boolean.toString(secureCookie));
                setUserSessionProperty(HTTP_ONLY_COOKIE_KEY, Boolean.toString(httpOnlyCookie));
                setUserSessionProperty(COOKIE_NAME_KEY, cookieName);
                final Subject clientSubject = new Subject();
                MessageInfo messageInfo = prepareMessageInfo(getHttpServletRequest(), getHttpServletResponse());
                if (process(messageInfo, clientSubject, callbacks)) {
                    return ISAuthConstants.LOGIN_SUCCEED;
                }
                throw new AuthLoginException(AUTH_RESOURCE_BUNDLE_NAME, "cookieNotValid", null);
            }
            default: {
                throw new AuthLoginException(AUTH_RESOURCE_BUNDLE_NAME, "incorrectState", null);
            }
        }
    }

    /**
     * If Jwt is invalid then throws LoginException, otherwise Jwt is valid and the realm is check to ensure
     * the user is authenticating in the same realm.
     *
     * @param messageInfo {@inheritDoc}
     * @param clientSubject {@inheritDoc}
     * @param callbacks {@inheritDoc}
     * @return {@inheritDoc}
     * @throws LoginException {@inheritDoc}
     */
    @Override
    protected boolean process(MessageInfo messageInfo, Subject clientSubject, Callback[] callbacks)
            throws LoginException {

        Jwt jwt = getServerAuthModule().validateJwtSessionCookie(
                prepareMessageInfo(getHttpServletRequest(), getHttpServletResponse()));

        if (jwt == null) {
            //BAD
            throw new AuthLoginException(AUTH_RESOURCE_BUNDLE_NAME, "cookieNotValid", null);
        } else {
            //GOOD
            Map<String, Object> claimsSetContext = jwt.getClaimsSet().getClaim(AuthNFilter.ATTRIBUTE_AUTH_CONTEXT, Map.class);
            if(claimsSetContext == null) {
                throw new AuthLoginException(AUTH_RESOURCE_BUNDLE_NAME, "jaspiContextNotFound", null);
            }

            // Need to check realm
            String jwtRealm = (String) claimsSetContext.get(OPENAM_REALM_CLAIM_KEY);
            if (!getRequestOrg().equals(jwtRealm)) {
                throw new AuthLoginException(AUTH_RESOURCE_BUNDLE_NAME, "authFailedDiffRealm", null);
            }

            // Need to get user from jwt to use in Principal
            final String username = (String) claimsSetContext.get(OPENAM_USER_CLAIM_KEY);
            principal = new Principal() {
                public String getName() {
                    return username;
                }
            };

            setUserSessionProperty(JwtSessionModule.JWT_VALIDATED_KEY, Boolean.TRUE.toString());
            return true;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Principal getPrincipal() {
        return principal;
    }

    /**
     * Initialises the JwtSessionModule for use by the Post Authentication Process.
     *
     * @param requestParamsMap {@inheritDoc}
     * @param request {@inheritDoc}
     * @param response {@inheritDoc}
     * @param ssoToken {@inheritDoc}
     * @return {@inheritDoc}
     * @throws AuthenticationException {@inheritDoc}
     */
    @Override
    protected Map<String, Object> initialize(Map requestParamsMap, HttpServletRequest request,
            HttpServletResponse response, SSOToken ssoToken) throws AuthenticationException {

        try {
            final String tokenIdleTime = ssoToken.getProperty(JwtSessionModule.TOKEN_IDLE_TIME_CLAIM_KEY);
            final String maxTokenLife = ssoToken.getProperty(JwtSessionModule.MAX_TOKEN_LIFE_KEY);
            final String realm = ssoToken.getProperty(SSO_TOKEN_ORGANIZATION_PROPERTY_KEY);
            boolean secureCookie = Boolean.parseBoolean(ssoToken.getProperty(SECURE_COOKIE_KEY));
            boolean httpOnlyCookie = Boolean.parseBoolean(ssoToken.getProperty(HTTP_ONLY_COOKIE_KEY));
            String cookieName = ssoToken.getProperty(COOKIE_NAME_KEY);
            
            return initialize(tokenIdleTime, maxTokenLife, realm, secureCookie, httpOnlyCookie, cookieName);
        } catch (SSOException e) {
            DEBUG.error("Could not initialise the Auth Module", e);
            throw new AuthenticationException(e.getLocalizedMessage());
        } catch (SMSException e) {
            DEBUG.error("Could not initialise the Auth Module", e);
            throw new AuthenticationException(e.getLocalizedMessage());
        }
    }

    /**
     * Sets the required information that needs to be in the jwt.
     *
     * @param messageInfo {@inheritDoc}
     * @param requestParamsMap {@inheritDoc}
     * @param request {@inheritDoc}
     * @param response {@inheritDoc}
     * @param ssoToken {@inheritDoc}
     * @throws AuthenticationException {@inheritDoc}
     */
    @Override
    public void onLoginSuccess(MessageInfo messageInfo, Map requestParamsMap, HttpServletRequest request,
            HttpServletResponse response, SSOToken ssoToken) throws AuthenticationException {
        try {
            Map<String, Object> contextMap = getServerAuthModule().getContextMap(messageInfo);

            contextMap.put(OPENAM_USER_CLAIM_KEY, ssoToken.getPrincipal().getName());
            contextMap.put(OPENAM_AUTH_TYPE_CLAIM_KEY, ssoToken.getAuthType());
            contextMap.put(OPENAM_SESSION_ID_CLAIM_KEY, ssoToken.getTokenID().toString());
            contextMap.put(OPENAM_REALM_CLAIM_KEY, ssoToken.getProperty(SSO_TOKEN_ORGANIZATION_PROPERTY_KEY));
            String jwtString = ssoToken.getProperty(JwtSessionModule.JWT_VALIDATED_KEY);
            if (jwtString != null) {
                messageInfo.getMap().put(JwtSessionModule.JWT_VALIDATED_KEY, Boolean.parseBoolean(jwtString));
            }
        } catch (SSOException e) {
            DEBUG.error("Could not secure response", e);
            throw new AuthenticationException(e.getLocalizedMessage());
        }
    }

    /**
     * Deletes the persistent cookie if authentication fails for some reason.
     *
     * @param requestParamsMap {@inheritDoc}
     * @param request {@inheritDoc}
     * @param response {@inheritDoc}
     */
    @Override
    public void onLoginFailure(Map requestParamsMap, HttpServletRequest request, HttpServletResponse response) {
        //TODO would need to get the initialization config from the JWT? before attempting to delete the cookie
        //getServerAuthModule().deleteSessionJwtCookie(response);
    }

    /**
     * Deletes the persistent cookie on logout.
     *
     * @param request {@inheritDoc}
     * @param response {@inheritDoc}
     * @param ssoToken {@inheritDoc}
     */
    @Override
    public void onLogout(HttpServletRequest request, HttpServletResponse response, SSOToken ssoToken) {
        try {
            Map<String, Object> config = initialize(null, request, response, ssoToken);
            getServerAuthModule().initialize(createRequestMessagePolicy(), null, null, config);
            getServerAuthModule().deleteSessionJwtCookie(response);
        } catch (AuthenticationException e) {
            DEBUG.error("Failed to initialise the underlying JASPI Server Auth Module.", e);
        } catch (AuthException e) {
            DEBUG.error("Failed to initialise the underlying JASPI Server Auth Module.", e);
        }
    }

    /**
     * Gets the Key alias for the realm.
     *
     * @param orgName The organisation name for the realm.
     * @return The key alias.
     * @throws SSOException If there is a problem getting the key alias.
     * @throws SMSException If there is a problem getting the key alias.
     */
    protected String getKeyAlias(String orgName) throws SSOException, SMSException {

        SSOToken token = AccessController.doPrivileged(AdminTokenAction.getInstance());

        ServiceConfigManager scm = new ServiceConfigManager(AUTH_SERVICE_NAME, token);

        ServiceConfig orgConfig = scm.getOrganizationConfig(orgName, null);
        String keyAlias = CollectionHelper.getMapAttr(orgConfig.getAttributes(), AUTH_KEY_ALIAS);

        return keyAlias;
    }
}
