package com.sun.identity.authentication.kamome;

import java.util.List;
import java.util.Map;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.spi.AMPostAuthProcessInterface;
import com.sun.identity.authentication.spi.AuthenticationException;
import com.sun.identity.shared.debug.Debug;

/**
 * 認証ポストプロセスクラス - パスワード初期設定リダイレクト
 * @author taisei.morigami
 *
 */
public class PasswordInitRedirectorProcess implements AMPostAuthProcessInterface {

    /** デバッグ */
    private static Debug DEBUG = Debug.getInstance(PasswordInitRedirectorProcess.class.getName());
    /** リダイレクト用URLが定義されているプロパティ名 */
    private static final String LOGIN_SUCCESS_URL_PROPERTY = "iplanet-am-user-success-url";
    /** プロパティファイル */
    private static ResourceBundle resource = PropertyResourceBundle.getBundle("PwdInitResource");

    /**
     * Post processing on successful authentication.
     * @param requestParamsMap contains HttpServletRequest parameters
     * @param request HttpServlet  request
     * @param response HttpServlet response
     * @param ssoToken user's session
     * @exception AuthenticationException if there is an error.
     */
    @Override
    public void onLoginSuccess(Map requestParamsMap, HttpServletRequest request, HttpServletResponse response,
            SSOToken ssoToken)
            throws AuthenticationException {
        DEBUG.message(getClass().getName() + "#onLoginSuccess() called.");

        String realm = requestParamsMap.containsKey("realm") ? (String) requestParamsMap.get("realm") : "";

        String loginId = null;
        try {
            loginId = ssoToken.getPrincipal().getName();
            int position = loginId.indexOf(",");
            loginId = loginId.substring(3, position);
        } catch (SSOException e) {
            e.printStackTrace();
            DEBUG.error("Cannot get user id.", e);
            return;
        }

        DEBUG.message("realm=" + realm + ",loginId=" + loginId);

        if (loginId.toLowerCase().contains("amadmin")) {
            return;
        }

        LdapContext context = null;
        try {
            String url = resource.getString("ldap.url");
            String user = resource.getString("ldap.user");
            String password = resource.getString("ldap.password");
            String baseDN = resource.getString("ldap.baseDN");

            DEBUG.message("url=" + url + ",user=" + user + ",password=" + password);

            // LDAP検索
            context = LdapUtil.createContext(url, user, password);
            LdapSearcher searcher = new LdapSearcher(context);
            String filter = "(&(objectClass=inetOrgPerson)(uid=" + loginId + "))";

            List<LdapResult> list = searcher.search(baseDN, filter);
            if (list.isEmpty()) {
                DEBUG.error("Do not find user:realm=" + realm + ",loginId=" + loginId);
            } else if (list.size() != 1) {
                StringBuilder sb = new StringBuilder("[");
                for (LdapResult result : list) {
                    sb.append("dn=");
                    sb.append(result.getAttribute("dn")).append(",");
                }
                DEBUG.error("Find duplicate users:" + sb.append("]").toString());
            } else {
                LdapResult result = (LdapResult) list.get(0);
                DEBUG.message(result.toString());
                if (!result.containsAttribute(LOGIN_SUCCESS_URL_PROPERTY)) {
                    return;
                }
                String redirect = result.getAttribute(LOGIN_SUCCESS_URL_PROPERTY);
                DEBUG.message("Redirect to " + redirect);
                request.setAttribute("PostProcessLoginSuccessURL", redirect);
            }
            return;
        } catch (NamingException e) {
            DEBUG.error(e.getMessage(), e);
        } finally {
            if (context != null) {
                try {
                    context.close();
                } catch (NamingException e) {
                }
            }
        }
    }

    /**
     * Post processing on failed authentication.
     * @param requestParamsMap contains HttpServletRequest parameters
     * @param req HttpServlet request
     * @param res HttpServlet response
     * @throws AuthenticationException if there is an error
     */
    @Override
    public void onLoginFailure(Map requestParamsMap, HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException {
        DEBUG.message("PasswordInitRedirectorProcess.onLoginFailure: called");
    }

    /**
     * Post processing on Logout.
     * @param req HttpServlet request
     * @param res HttpServlet response
     * @param ssoToken user's session
     * @throws AuthenticationException if there is an error
     */
    @Override
    public void onLogout(HttpServletRequest req, HttpServletResponse res, SSOToken ssoToken)
            throws AuthenticationException {
        DEBUG.message("PasswordInitRedirectorProcess.onLogout called");
    }
}
