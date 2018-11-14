package com.sun.identity.authentication.modules.userid;

import java.security.Principal;
import java.util.Map;
import java.util.ResourceBundle;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

import org.forgerock.openam.utils.StringUtils;

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.ServiceConfig;

/**
 * DataStore認証をもとに作成。
 * パスワードは入力されないため、処理から削除。
 * ユーザの有無は確認しない。入力値がブランクかどうかはチェック。
 * 
 * @author taisei.morigami
 *
 */
public class UserId extends AMLoginModule {
    // local variables
    ResourceBundle bundle = null;
    protected String validatedUserID;
    private String userName;
    private ServiceConfig sc;
    private int currentState;

    private static String AUTHLEVEL = "sunAMAuthUserIdAuthLevel";
    private static final String INVALID_CHARS = "iplanet-am-auth-ldap-invalid-chars";

    private Map sharedState;
    public Map currentConfig;

    protected Debug debug = null;
    protected String amAuthUserId;
    protected Principal userPrincipal;

    public UserId() {
        amAuthUserId = "amAuthUserId";
        debug = Debug.getInstance(amAuthUserId);
    }

    public void init(Subject subject, Map sharedState, Map options) {
        sc = (ServiceConfig) options.get("ServiceConfig");
        currentConfig = options;
        String authLevel = CollectionHelper.getMapAttr(options, AUTHLEVEL);
        if (authLevel != null) {
            try {
                setAuthLevel(Integer.parseInt(authLevel));
            } catch (Exception e) {
                debug.error("Unable to set auth level " + authLevel, e);
            }
        }
        java.util.Locale locale = getLoginLocale();
        bundle = amCache.getResBundle(amAuthUserId, locale);
        if (debug.messageEnabled()) {
            debug.message("UserId resbundle locale=" + locale);
        }
        this.sharedState = sharedState;
    }

    public int process(Callback[] callbacks, int state) throws AuthLoginException {
        currentState = state;
        int retVal = 0;
        Callback[] idCallbacks = new Callback[2];

        if (currentState == ISAuthConstants.LOGIN_START) {
            if (callbacks != null && callbacks.length == 0) {
                userName = (String) sharedState.get(getUserKey());
                if (userName == null) {
                    return ISAuthConstants.LOGIN_START;
                }
                NameCallback nameCallback = new NameCallback("dummy");
                nameCallback.setName(userName);
                idCallbacks[0] = nameCallback;
            } else {
                idCallbacks = callbacks;
                userName = ((NameCallback) callbacks[0]).getName();
            }
            if (StringUtils.isEmpty(userName)) {
                debug.message("amAuthUserId authFailed user name is empty");
                setFailureID(userName);
                throw new AuthLoginException(amAuthUserId, "authFailed", null);
            }
            storeUsernamePasswd(userName, "");
            validateUserName(userName, CollectionHelper.getMapAttr(currentConfig, INVALID_CHARS));
            validatedUserID = userName;
            retVal = ISAuthConstants.LOGIN_SUCCEED;
        } else {
            debug.message("amAuthUserId authFailed");
            setFailureID(userName);
            throw new AuthLoginException(amAuthUserId, "authFailed", null);
        }

        return retVal;
    }

    public java.security.Principal getPrincipal() {
        if (userPrincipal != null) {
            return userPrincipal;
        } else if (validatedUserID != null) {
            userPrincipal = new UserIdPrincipal(validatedUserID);
            return userPrincipal;
        } else {
            return null;
        }
    }

    public void destroyModuleState() {
        validatedUserID = null;
        userPrincipal = null;
    }

    public void nullifyUsedVars() {
        bundle = null;
        userName = null;
        sc = null;
        sharedState = null;
        currentConfig = null;
        amAuthUserId = null;
    }
}
