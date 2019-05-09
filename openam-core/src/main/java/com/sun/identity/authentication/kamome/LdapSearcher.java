package com.sun.identity.authentication.kamome;

import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

/**
 * LDAPを検索する。ldapsearchコマンドのラッパー。
 */
public class LdapSearcher {

    /** LDAPコンテキスト */
    private LdapContext context;

    /**
     * コンストラクタ
     * @param context LDAPコンテキスト
     * @throws NamingException
     */
    public LdapSearcher(LdapContext context) throws NamingException {
        this.context = context;
    }

    /**
     * LDAP検索
     * @param baseDN 検索するDN
     * @param filter 検索フィルタ
     * @return 検索結果
     * @throws NamingException
     */
    public List<LdapResult> search(String baseDN, String filter) throws NamingException {
        SearchControls control = new SearchControls(SearchControls.SUBTREE_SCOPE, 0, 0, null, false, false);
        NamingEnumeration<SearchResult> enu = context.search(baseDN, filter, control);

        List<LdapResult> list = new ArrayList<LdapResult>();
        while (enu.hasMoreElements()) {
            SearchResult res = enu.nextElement();
            NamingEnumeration<? extends Attribute> attributes = res.getAttributes().getAll();

            // １レコード
            LdapResult result = new LdapResult();
            while (attributes.hasMoreElements()) {
                Attribute attribute = attributes.nextElement();

                // 属性
                NamingEnumeration<?> e = attribute.getAll();
                while (e.hasMoreElements()) {
                    result.add(attribute.getID(), e.nextElement().toString());
                }
            }
            list.add(result);
        }
        return list;
    }
}
