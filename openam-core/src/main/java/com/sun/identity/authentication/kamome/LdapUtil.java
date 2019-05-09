package com.sun.identity.authentication.kamome;

import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

/**
 * LDAPユーティリティ
 */
public class LdapUtil {

    /**
     * コンテキストを取得する
     * @param url LDAPサーバのURL
     * @param principal バインドユーザDN
     * @param credentials バインドパスワード
     * @return LDAPコンテキスト
     * @throws NamingException
     */
    public static LdapContext createContext(String url, String principal, String credentials) throws NamingException {
        Properties env = new Properties();
        env.setProperty(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.setProperty(Context.PROVIDER_URL, url); // 接続先
        env.setProperty(Context.SECURITY_PRINCIPAL, principal); // ログインDN
        env.setProperty(Context.SECURITY_CREDENTIALS, credentials); // パスワード

        return new InitialLdapContext(env, null);
    }
}