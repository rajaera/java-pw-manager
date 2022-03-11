/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package passwordmanager;

import crypto.AESUtil;
import java.security.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Eranga
 */
public class PasswordManager {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        try {
            String input = "test123";
            
            SecretKey key = AESUtil.getKeyFromPassword(input, "rajaera@gmail.com");
            IvParameterSpec ivParameterSpec = AESUtil.generateIv();
            String algorithm = "AES/CBC/PKCS5Padding";
            String cypherText = AESUtil.encrypt(algorithm, input, key, ivParameterSpec);
            String plainText = AESUtil.decrypt(algorithm, cypherText, key, ivParameterSpec);
            
            System.err.println(input + " " + cypherText);
        } catch(Exception ex) {
            ex.printStackTrace();
        }
    }
    
    /*
    public static String encrypt(String value) {
        try {
            Security.setProperty("crypto.policy", "unlimited");
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            
            
            KeySpec spec = new PBEKeySpec(value.toCharArray(), salt, 65536, 128);
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            
            byte[] key = f.generateSecret(spec).getEncoded();   
            
            
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            
            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
             
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            
           
            
            byte[] encrypted = cipher.doFinal(value.getBytes());
            byte[] encodedBytes = Base64.getEncoder().encode(encrypted);
            
            System.err.println("encrypted string : " + new String(encodedBytes));
            
            System.err.println(key.length);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        
        return null;
    }
*/
    
}
