/*
 * パスワード暗号化（ソルト+ハッシュ）※SHA-256
 * かもめエンジニアリング 山本 2017/11/10
 */

package com.iplanet.services.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class EncryptSaltHash {
	
	/*
	 * 入力したユーザー情報からパスワードを暗号化する
	 * 引数1：inputUid：入力されたユーザーID
	 * 引数2：inputPass：入力されたパスワード
	 * 戻り値：inputUid、inputPassの順で文字列結合した値をハッシュ化（SHA-256）したもの
	 */
	public static String encryptionPassword(String inputUid, String inputPass) {
		
		String inputValue = null;
		StringBuilder sBuf = new StringBuilder();
		
		// 入力されたユーザーID、入力されたパスワードの順で文字列結合
		sBuf.append(inputUid);
		sBuf.append(inputPass);
		inputValue = sBuf.toString();
		
		return inputValue = toEncryptedHashValue(inputValue);
	}
	
	private static String toEncryptedHashValue(String value) {
		
	    MessageDigest md = null;
	    StringBuilder sb = null;
	    
	    String algorithmName = "SHA-256";
	    
	    try {
	        md = MessageDigest.getInstance(algorithmName);
	    } catch (NoSuchAlgorithmException e) {
	        e.printStackTrace();
	    }
	    
	    md.update(value.getBytes(StandardCharsets.UTF_8));
	    
	    sb = new StringBuilder();
	    
	    for (byte b : md.digest()) {
	        String hex = String.format("%02x", b);
	        sb.append(hex);
	    }
	    
	    return sb.toString();
	}
	
}