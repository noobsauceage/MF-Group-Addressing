/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.umass.cs.gcrs.gcrs;

import edu.umass.cs.gcrs.utilities.Utils;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author westy
 */
public class Crypt {

  public static void main(String[] args) {
    new Crypt().runTest();
  }

  private void runTest() {
    // Generate new key
    try {
      KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
      PrivateKey privateKey = keyPair.getPrivate();
      String plaintext = "This is the message being signed";

      // Compute signature
      Signature instance = Signature.getInstance("SHA1withRSA");
      instance.initSign(privateKey);
      instance.update((plaintext).getBytes());
      byte[] signature = instance.sign();

      // Compute digest
      MessageDigest sha1 = MessageDigest.getInstance("SHA1");
      byte[] digest = sha1.digest((plaintext).getBytes());

      // Encrypt digest
      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, privateKey);
      byte[] cipherText = cipher.doFinal(digest);
      
      // Display results
      System.out.println("Input data: " + plaintext);
      System.out.println("Digest: " + Utils.toHex(digest));
      System.out.println("Cipher text: " + Utils.toHex(cipherText));
      System.out.println("Signature: " + Utils.toHex(signature));
    } catch (BadPaddingException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (IllegalBlockSizeException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (InvalidKeyException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (NoSuchAlgorithmException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (NoSuchPaddingException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (SignatureException e) {
      GCRS.getLogger().severe(e.toString());
    }


  }
}
