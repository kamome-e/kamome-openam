package com.sun.identity.authentication.modules.jdbc;

import java.security.NoSuchAlgorithmException;

import com.iplanet.services.util.OpenLDAPEncryption;

/**
 * パスワード暗号化ロジック OpenLDAP方式(SSHA)
 * かもめエンジニアリング 山本 2017.11.17
 */
public class EncryptedTextTransform implements JDBCPasswordSyntaxTransform  {

    /** ハッシュ化のアルゴリズム：SHA-1 */
    private static final String ALG_SHA1 = "SHA-1";
    /** ハッシュ化のアルゴリズム：SHA-256 */
    private static final String ALG_SHA256 = "SHA-256";
    /** ハッシュ化のアルゴリズム：SHA-512 */
    private static final String ALG_SHA512 = "SHA-512";

    /**
     * Creates a new instance of <code>EncryptedTextTransform</code>.
     */
    public EncryptedTextTransform() {
    }

    /**
     * パスワードのハッシュ化（登録用）
     * @param inputPass
     * @return
     * @throws NoSuchAlgorithmException
     */
    public String transform(String inputPass) throws NoSuchAlgorithmException {

        OpenLDAPEncryption clsLDAPEnc = new OpenLDAPEncryption();

        // Saltのランダム生成
        byte[] bRndSalt = clsLDAPEnc.generateSalt();

        // 入力したパスワードのハッシュ化
        byte[] hashedPass = clsLDAPEnc.encryptionPassword1(ALG_SHA1, inputPass, bRndSalt);
        String encPass = clsLDAPEnc.encryptionPassword2(ALG_SHA1, hashedPass, bRndSalt);

        return encPass;
    }

    /**
     * パスワードのハッシュ化（ログイン時の検証用）
     * @param extPass
     * @param inputPass
     * @return
     * @throws NoSuchAlgorithmException
     */
    public byte[] transformCompare(String extPass, String inputPass) throws NoSuchAlgorithmException {

        OpenLDAPEncryption clsLDAPEnc = new OpenLDAPEncryption();

        // Saltの抽出
        byte[] bExtSalt = clsLDAPEnc.extractionSalt(ALG_SHA1, extPass);

        // 入力したパスワードの暗号化
        byte[] hashedPass = clsLDAPEnc.encryptionPassword1(ALG_SHA1, inputPass, bExtSalt);

        return hashedPass;
    }

    /**
     * @param extPass
     * @return
     * @throws NoSuchAlgorithmException
     */
    public byte[] decryptionPassword(String extPass) throws NoSuchAlgorithmException {
        OpenLDAPEncryption clsLDAPEnc = new OpenLDAPEncryption();
        return clsLDAPEnc.decryptionPassword(ALG_SHA1, extPass);
    }
}
