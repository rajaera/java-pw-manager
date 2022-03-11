/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Eranga
 */
public class AESUtil {
    public static SecretKey generateKey(int n) 
            throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        
        return key;
    }
    
    //Generate key from a given password and salt
    public static SecretKey getKeyFromPassword(String password, String salt) 
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 16384, 128);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        
        return secret;
    }
    
    //Initialization Vector - IV
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    
    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv) 
            throws NoSuchPaddingException, 
            NoSuchAlgorithmException, 
            InvalidAlgorithmParameterException, 
            InvalidKeyException,
            BadPaddingException, 
            IllegalBlockSizeException {
        
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] cipherText = cipher.doFinal(input.getBytes());
        
        return Base64.getEncoder().encodeToString(cipherText);
    }
    
    public static String decrypt(String algorithm, String cypherText, SecretKey key, IvParameterSpec iv) 
            throws NoSuchPaddingException, 
            NoSuchAlgorithmException, 
            InvalidAlgorithmParameterException, 
            InvalidKeyException, 
            BadPaddingException, 
            IllegalBlockSizeException {
        
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plianText = cipher.doFinal(Base64.getDecoder().decode(cypherText));
        
        return new String(plianText);
    }
}
