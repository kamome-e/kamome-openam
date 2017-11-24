/*
 * 文字列の暗号化生成クラス（強化型）
 * かもめエンジニアリング 山本 2017.11.14
 * ※未使用（今後実装するかも？）
 */

package com.iplanet.services.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.RandomStringUtils;

public class RobustCrypt {
	
	private static final String ALGORITHM_AES = "AES";            // 暗号化方式「AES(Advanced Encryption Standard)」
	private static final String ENC_METHOD = "AES/CBC/PKCS5Padding";
	private static final int RANDOM_DIGIT = 16;                   // IV用の桁数
	private static final String SECRET_KEY = "kamome_sso_crypt";  // 暗号解読キーの値
	private static final String PATH_FILE_KEY = "kamome-sso.key"; // 保存PATH:暗号解読キーファイル
	private static final String PATH_FILE_IV = "kamome-sso.iv";   // 保存PATH:IV情報ファイル
	
	/**
	 * パスワードの暗号化
	 */
	public static String encryptPass(String inputPass)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException
			, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException
			, BadPaddingException {
		
		String resultInput = null;
		
		
		// 暗号解読キーファイル、IV情報ファイルを検索して存在しないファイルは新たに作成する
		if (!FileExist(PATH_FILE_KEY)) {genFileKEY(PATH_FILE_KEY);}
		if (!FileExist(PATH_FILE_IV)) {genFileIV(PATH_FILE_IV);}
		
		// 暗号化時のスタートブロック用の初期値を作成
		IvParameterSpec iv = new IvParameterSpec(readBytes(PATH_FILE_IV));
		
		// 暗号方式＋解読キーのセットを作成
		SecretKeySpec key = new SecretKeySpec(readBytes(PATH_FILE_KEY), ALGORITHM_AES);
		
		Cipher encrypter = Cipher.getInstance(ENC_METHOD); // 暗号方式と生成方式などを指定して暗号器を作成
       encrypter.init(Cipher.ENCRYPT_MODE, key, iv);      // 暗号器を暗号化モードにセットする
        
		resultInput = encryptString(inputPass, encrypter);
		
		return resultInput;
	}
	
	/**
	 * パスワードの複合化
	 */
	public static String decryptPass(String encryptedPass)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
			, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		String decryptedPass = null;
		
		// 暗号解読キーファイル、IV情報ファイルのいずれかが存在しない場合はNullを返す
		if (!FileExist(PATH_FILE_KEY) || !FileExist(PATH_FILE_IV)) {
			return null;
		} else {
			
			// 複合化時のスタートブロック用の初期値を作成
			IvParameterSpec iv = new IvParameterSpec(readBytes(PATH_FILE_IV));
			
			// 暗号方式＋解読キーのセットを作成
			SecretKeySpec key = new SecretKeySpec(readBytes(PATH_FILE_KEY), ALGORITHM_AES);
			
			Cipher decrypter = Cipher.getInstance(ENC_METHOD); // 暗号方式と生成方式などを指定して暗号器を作成
			decrypter.init(Cipher.DECRYPT_MODE, key, iv);      // 暗号器を複合化モードにセットする
			
			decryptedPass = decryptString(encryptedPass, decrypter);
			
			return decryptedPass;
		}
	}
	
	/**
	 * ファイルの存在確認
	 */
	private static boolean FileExist(String filePath) {
		
		File file = new File(filePath);
		
		if (file.exists()){
		    return true;
		}else{
		    return false;
		}
	}

	/**
	 * 暗号解読キーファイルの作成
	 */
	private static void genFileKEY(String filePath) throws UnsupportedEncodingException {
		
		byte[] key = SECRET_KEY.getBytes(StandardCharsets.UTF_8); // 暗号解読キー(128ビット固定長)
		genFileCommon(key, filePath);
	}
	
	/**
	 * IV情報ファイルの作成
	 */
	private static void genFileIV(String filePath) throws UnsupportedEncodingException {
		
		byte[] iv  = RandomStringUtils.randomAlphanumeric(RANDOM_DIGIT).getBytes(StandardCharsets.UTF_8); // IV(128ビット固定長)
		genFileCommon(iv, filePath);
	}
	
	/**
	 * ファイルの作成
	 */
	private static void genFileCommon(byte[] bVal, String filePath) {
				
		try(ObjectOutputStream o = new ObjectOutputStream(new FileOutputStream(filePath))) {
            o.write(bVal);
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	/**
	 * ファイルの読み込み
	 */
	public static byte[] readBytes(String filePath) {
		
        byte[] b = new byte[RANDOM_DIGIT];
        
        try(ObjectInputStream in = new ObjectInputStream(new FileInputStream(filePath))) {
            in.read(b, 0, RANDOM_DIGIT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return b;
    }
	
	/**
	 * 文字列の暗号化処理
	 */
	private static String encryptString(String input, Cipher encrypter)
			throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		
		byte[] encText = encrypter.doFinal(input.getBytes(StandardCharsets.UTF_8)); // 暗号化する
		byte[] encText64 = Base64.getEncoder().encode(encText);                     // Base64でエンコード
		
		return new String(encText64);
	}
	
	/**
	 * 文字列の複合化処理
	 */
	private static String decryptString(String encText64, Cipher decrypter)
			throws IllegalBlockSizeException, BadPaddingException {
		
		byte[] encText = Base64.getDecoder().decode(encText64); // 暗号文字列を元のバイナリに戻す
		byte[] decText = decrypter.doFinal(encText);            // 復号化する
		
		return new String(decText);
	}

}