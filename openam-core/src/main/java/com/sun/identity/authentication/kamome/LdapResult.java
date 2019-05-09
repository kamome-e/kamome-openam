package com.sun.identity.authentication.kamome;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class LdapResult {

    /** 検索結果 */
    private Map<String, Set<String>> map = new HashMap<String, Set<String>>();

    /**
     * 属性は存在するか？
     * @param name 属性名
     * @return true：存在する、false：存在しない。
     */
    public boolean containsAttribute(String name) {
        return map.containsKey(name);
    }

    /**
     * 属性値を１つ取得する。<br>
     * 複数存在する場合はどれが１つを取得する。
     * 複数取得する場合は、<pre>getAttributeSet()</pre>を使用する。
     * @param name 属性名
     * @return 属性値。存在しなかった場合はnull。
     * @see jp.nri.ossc.opensso.ldap.LdapResult#getAttributeSet(String).
     */
    public String getAttribute(String name) {
        if (containsAttribute(name)) {
            // 最初の要素のみ取得
            return getAttributeSet(name).iterator().next();
        }
        return null;
    }

    /**
     * 属性値を取得する。
     * @param name 属性名
     * @return 属性値
     */
    public Set<String> getAttributeSet(String name) {
        return map.get(name);
    }

    /**
     * 属性名をすべて取得する
     * @return 属性名のSet
     */
    public Set<String> getAttributeNames() {
        return map.keySet();
    }

    /**
     * 属性数を取得する
     * @return 属性の数
     */
    public int size() {
        return map.size();
    }

    /**
     * 属性名と属性値の一覧を文字列で出力する。
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Set<String>> entry : map.entrySet()) {
            sb.append("{").append(entry.getKey()).append("=[");
            for (String value : entry.getValue()) {
                sb.append(value).append(",");
            }
            sb.append("]}");
        }
        return sb.toString();
    }

    /**
     * 属性を追加
     * @param name 属性名
     * @param value 属性値
     */
    void add(String name, String value) {
        if (map.containsKey(name)) {
            Set<String> set = map.get(name);
            set.add(value);
        } else {
            Set<String> set = new HashSet<String>();
            set.add(value);
            map.put(name, set);
        }
    }
}
