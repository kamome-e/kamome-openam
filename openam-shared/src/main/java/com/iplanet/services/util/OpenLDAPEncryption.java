package com.iplanet.services.util;

import java.nio.charset.StandardCharsets;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * パスワード暗号化ロジック OpenLDAP方式(SSHA)
 * かもめエンジニアリング 山本 2017.11.17
 * 
 * 暗号化ロジック
 * 1：ランダムでSaltを生成
 * 2：(byte化した)パスワード + (byte化した)Salt
 * 3：ハッシュ化(SHA-1)
 * 4：Base64でエンコード
 * 5：エンコードした値 + (byte化した)Salt
 * 6：アルゴリズム方式を先頭に表記
 */
public class OpenLDAPEncryption {
	
	private static final int DIGIT_SALT = 16; // Saltのbyte数
	
	private static final int DIGIT_HASH_SHA1 = 20;   // ハッシュ値のbyte数：20byte
	private static final int DIGIT_HASH_SHA256 = 32; // ハッシュ値のbyte数：32byte
	private static final int DIGIT_HASH_SHA512 = 64; // ハッシュ値のbyte数：64byte
	
	private static final String ALG_SHA1 = "SHA-1";     // ハッシュ化のアルゴリズム：SHA-1
	private static final String ALG_SHA256 = "SHA-256"; // ハッシュ化のアルゴリズム：SHA-256
	private static final String ALG_SHA512 = "SHA-512"; // ハッシュ化のアルゴリズム：SHA-512
	
	private static final String SHOW_ALG_SSHA = "{SSHA}";       // アルゴリズムの表記方法：SSHA
	private static final String SHOW_ALG_SSHA256 = "{SSHA256}"; // アルゴリズムの表記方法：SSHA256
	private static final String SHOW_ALG_SSHA512 = "{SSHA512}"; // アルゴリズムの表記方法：SSHA512
	
	/**
	 * ハッシュ化アルゴリズムの設定 ※引数がどのアルゴリズムにも該当しない場合はSSHAに強制的に設定
	 * @param alg
	 */
	private static Object[] initAlgorithm(String alg) {
		
		Object algData[];
		algData = new Object[3];
		
		switch (alg) {
		  case ALG_SHA1:
			  algData[0] = DIGIT_HASH_SHA1;
			  algData[1] = ALG_SHA1;
			  algData[2] = SHOW_ALG_SSHA;
			  break;
			  
		  case ALG_SHA256:
			  algData[0] = DIGIT_HASH_SHA256;
			  algData[1] = ALG_SHA256;
			  algData[2] = SHOW_ALG_SSHA256;
			  break;
			  
		  case ALG_SHA512:
			  algData[0] = DIGIT_HASH_SHA512;
			  algData[1] = ALG_SHA512;
			  algData[2] = SHOW_ALG_SSHA512;
			  break;
			  
		  default:
			  algData[0] = DIGIT_HASH_SHA1;
			  algData[1] = ALG_SHA1;
			  algData[2] = SHOW_ALG_SSHA;
			  break;
		}
		
		return algData;
	}

	/**
	 * Saltの抽出
	 * @param alg
	 * @param getPass
	 * @return
	 */
	public byte[] extractionSalt(String alg, String getPass) {
		
		Object algData[];
		algData = initAlgorithm(alg); // ハッシュ化アルゴリズムの設定
		
		// DBから取得したパスワードをBase64でデコード
		String sNoSalt = getPass.replace(algData[2].toString(), ""); // 先頭のアルゴリズム表記を削除
		byte[] bNoSalt = sNoSalt.getBytes(StandardCharsets.UTF_8); // 文字列をバイトに変換
		byte[] b64DecPass = Base64.getDecoder().decode(bNoSalt); // Base64でデコード
		
		// Saltを抜き出す
		byte[] bSalt = Arrays.copyOfRange(b64DecPass, Integer.parseInt(algData[0].toString()), b64DecPass.length);
		
		return bSalt;
	}
	
	/**
	 * Saltのランダム生成
	 * @return
	 * @throws NoSuchAlgorithmException 
	 */
	public byte[] generateSalt() throws NoSuchAlgorithmException {
		
		// byte型で設定したバイト長のランダムなデータを生成
		byte[] bRndSalt = new byte[DIGIT_SALT];
		SecureRandom secRandom = SecureRandom.getInstance("SHA1PRNG");
    	secRandom.nextBytes(bRndSalt);
    	return bRndSalt;
	}
	
	/**
	 * 入力したパスワードのハッシュ化 (OpenLDAP方式) ※前半(認証時の比較用データ生成も兼ねる)
	 * @param alg
	 * @param sInputPass
	 * @param bRndSalt
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public byte[] encryptionPassword1(String alg, String sInputPass, byte[] bRndSalt) throws NoSuchAlgorithmException {
		
		Object algData[];
		algData = initAlgorithm(alg); // ハッシュ化アルゴリズムの設定
		
		// パスワード、生成したSaltの順で結合
		byte[] bInputPass = sInputPass.getBytes(StandardCharsets.UTF_8); // 文字列をバイトに変換
    	byte[] bPassSalt = new byte[bInputPass.length + bRndSalt.length];
    	System.arraycopy(bInputPass, 0, bPassSalt, 0, bInputPass.length);
    	System.arraycopy(bRndSalt, 0, bPassSalt, bInputPass.length, bRndSalt.length);
    	
    	// 結合した値をハッシュ化
    	MessageDigest md = MessageDigest.getInstance(algData[1].toString());
    	md.update(bPassSalt);
    	byte[] bHashed = md.digest(); // ハッシュ化されたパスワード
    	
    	return bHashed;
	}
	
	/**
	 * 入力したパスワードのハッシュ化 (OpenLDAP方式) ※後半
	 * @param alg
	 * @param bHashedPass
	 * @param bRndSalt
	 * @return
	 */
	public String encryptionPassword2(String alg, byte[] bHashedPass, byte[] bRndSalt) {
		
		Object algData[];
		algData = initAlgorithm(alg); // ハッシュ化アルゴリズムの設定
		
		// ハッシュ化した値と生成したSaltを結合
    	byte[] bHasedSalt = new byte[bHashedPass.length + bRndSalt.length];
		System.arraycopy(bHashedPass, 0, bHasedSalt, 0, bHashedPass.length);
    	System.arraycopy(bRndSalt, 0, bHasedSalt, bHashedPass.length, bRndSalt.length);
    	
    	// 結合した値をBase64でエンコード
    	byte[] b64HasedSalt = Base64.getEncoder().encode(bHasedSalt);
    	
    	// 出力する暗号化パスワードのフォーマットを整える
    	String s64HasedSalt = new String(b64HasedSalt, StandardCharsets.UTF_8); // バイトを文字列に変換
    	String sEncPass = algData[2].toString() + s64HasedSalt; // アルゴリズムを先頭に表記
    	
    	return sEncPass;
	}
	
	/**
	 * DBから抽出したパスワードを比較用の値に変換
	 * @param alg
	 * @param sExtPass
	 * @return
	 */
	public byte[] decryptionPassword(String alg, String sExtPass) {
		
		Object algData[];
		algData = initAlgorithm(alg); // ハッシュ化アルゴリズムの設定
		
		// Base64からデコード
		sExtPass = sExtPass.replace(algData[2].toString(), ""); // 先頭のアルゴリズム表記を削除
		byte[] bExtPass64 = sExtPass.getBytes(StandardCharsets.UTF_8); // 文字列をバイトに変換
		byte[] bExtPass = Base64.getDecoder().decode(bExtPass64);
		
		// デコードされたデータの最後尾にあるSaltを削除
		byte[] bNoSalt = new byte[Integer.parseInt(algData[0].toString())];
		System.arraycopy(bExtPass, 0, bNoSalt, 0, Integer.parseInt(algData[0].toString()));
		
		return bNoSalt;
	}
}
