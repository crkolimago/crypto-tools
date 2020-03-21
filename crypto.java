import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Scanner;

class crypto {

  /**
   * Generates a key for a symmetric key cryptosystem.
   *
   * @param instance symmetric key cryptosystem
   * @param keyLen   length of key
   * @return         symmetric key
   * @throws Exception
   */
  private static SecretKey generateKey(String instance, int keyLen) throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance(instance, "BC");
    keyGen.init(keyLen);
    return keyGen.generateKey();
  }

  /**
   * Generates a random iv for symmetric key cryptosystem
   *
   * @param instance    symmetric key cryptosystem
   * @return            unique iv
   * @throws Exception
   */
  private static IvParameterSpec generateIV(String instance) throws Exception {
    SecureRandom randomSecureRandom = new SecureRandom();
    Cipher cipher = Cipher.getInstance(instance, "BC");

    byte[] iv = new byte[cipher.getBlockSize()];

    randomSecureRandom.nextBytes(iv);
    return new IvParameterSpec(iv);
  }

  /**
   * Generates a key pair for a public key cryptosystem
   *
   * @param instance  public key cryptosystem
   * @param keyLen    length of keys
   * @return          pair of public and private keys
   * @throws Exception
   */
  private static KeyPair generateKeyPair(String instance, int keyLen) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(instance, "BC");
    keyGen.initialize(keyLen, new SecureRandom()); // add source of randomness
    return keyGen.generateKeyPair();
  }

  /**
   * Encrypts a message using a symmetric key cryptosystem
   *
   * @param key         secret key
   * @param plaintext   plaintext to be encrypted
   * @param instance    symmetric key cryptosystem
   * @return            encrypted message
   * @throws Exception
   */
  public static byte[] symmetric_encrypt(SecretKey key, IvParameterSpec iv, byte[] plaintext, String instance) throws Exception {
    Cipher cipher = Cipher.getInstance(instance, "BC");
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    return cipher.doFinal(plaintext);
  }

  /**
   * Decrypts a message using a symmetric key cryptosystem
   *
   * @param key         secret key
   * @param ciphertext  ciphertext to be decrypted
   * @param instance    symmetric key cryptosystem
   * @return            decrypted message
   * @throws Exception
   */
  public static byte[] symmetric_decrypt(SecretKey key, IvParameterSpec iv, byte[] ciphertext, String instance) throws Exception {
    Cipher cipher = Cipher.getInstance(instance, "BC");
    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    return cipher.doFinal(ciphertext);
  }

  /**
   * Encrypts a message using a public key cryptosystem
   *
   * @param key         public key
   * @param plaintext   plaintext to be encrypted
   * @param instance    public key cryptosystem
   * @return            encrypted message
   * @throws Exception
   */
  public static byte[] public_encrypt(PublicKey key, byte[] plaintext, String instance) throws Exception {
    Cipher cipher = Cipher.getInstance(instance, "BC");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    // System.out.println(cipher.getBlockSize());
    return cipher.doFinal(plaintext);
  }

  /**
   * Decrypts a message using a public key cryptosystem
   *
   * @param key         private key
   * @param ciphertext  cipher text to be decrypted
   * @param instance    public key cryptosystem
   * @return            decrypted message
   * @throws Exception
   */
  public static byte[] private_decrypt(PrivateKey key, byte[] ciphertext, String instance) throws Exception {
    Cipher cipher = Cipher.getInstance(instance, "BC");
    cipher.init(Cipher.DECRYPT_MODE, key);
    return cipher.doFinal(ciphertext);
  }

  /**
   * Signs a message using a hash algorithm and public key cryptosystem
   *
   * @param key         private key to sign the message with
   * @param plaintext   plaintext to be signed
   * @param instance    signing and verification instance
   * @return            message signature
   * @throws Exception
   */
  public static byte[] sign(PrivateKey key, byte[] plaintext, String instance) throws Exception {
    Signature signature = Signature.getInstance(instance, "BC");
    signature.initSign(key);
    signature.update(plaintext);

    return signature.sign();
  }

  /**
   * Verifies that a message is signed by the proper private key
   *
   * @param key         public key
   * @param plaintext   plain text to check signature
   * @param signature   signature of plaintext
   * @param instance    signing and verification instance
   * @return            true if the message was signature is correct
   * @throws Exception
   */
  public static boolean verify(PublicKey key, byte[] plaintext, byte[] signature, String instance) throws Exception {
    Signature publicSignature = Signature.getInstance(instance, "BC");
    publicSignature.initVerify(key);
    publicSignature.update(plaintext);

    return publicSignature.verify(signature);
  }

  public static void main(String[] args) throws Exception {
    SecretKey key;
    IvParameterSpec iv;
    KeyPair pair;
    byte[] encryptedText, decryptedText, signature;
    byte[] plainText = new byte[0];
    String userInput;
    boolean verified;

    /* init */

    // configure the unlimited strength jurisdiction policy files
    Security.setProperty("crypto.policy", "unlimited");
    // initialize bouncy castle as provider
    Security.addProvider(new BouncyCastleProvider());

    /* User Input */

    // input a line of text from the console

    Scanner input = new Scanner(System.in);

    System.out.println("Enter message to encrypt:");

    userInput = input.nextLine();

    // convert user input to UTF-8 byte array

    try {
      plainText = userInput.getBytes("UTF-8");
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    }

    System.out.printf("Plaintext: %s\n\n", new String(plainText));

    /* AES implementation */

    // generate key
    key = generateKey("AES", 256);
    iv = generateIV("AES");

    // encryption
    System.out.println("Encrypting with AES...");
    encryptedText = symmetric_encrypt(key, iv, plainText, "AES/CBC/PKCS7Padding"); // specify CBC
    System.out.printf("Ciphertext: %s\n", new String(encryptedText));

    // decryption
    System.out.println("Decrypting with AES...");
    decryptedText = symmetric_decrypt(key, iv, encryptedText, "AES/CBC/PKCS7Padding"); // specify CBC
    System.out.printf("Plaintext: %s\n", new String(decryptedText));

    System.out.println();

    // reset
    key = null;
    iv = null;
    encryptedText = null;
    decryptedText = null;

    /* TwoFish */
    // generate key
    key = generateKey("Twofish", 256);
    iv = generateIV("Twofish");

    // encryption
    System.out.println("Encrypting with Twofish...");
    encryptedText = symmetric_encrypt(key, iv, plainText, "Twofish/CBC/PKCS7Padding");
    System.out.printf("Ciphertext: %s\n", new String(encryptedText));

    // decryption
    System.out.println("Decrypting with Twofish...");
    decryptedText = symmetric_decrypt(key, iv, encryptedText, "Twofish/CBC/PKCS7Padding");
    System.out.printf("Plaintext: %s\n", new String(decryptedText));

    System.out.println();

    // reset
    encryptedText = null;
    decryptedText = null;

    /* RSA */

    // generate key pair
    pair = generateKeyPair("RSA", 2048);

    // encryption
    System.out.println("Encrypting with RSA...");
    encryptedText = public_encrypt(pair.getPublic(), plainText, "RSA");
    System.out.printf("Ciphertext: %s\n", new String(encryptedText));

    // decryption
    System.out.println("Decrypting with RSA...");
    decryptedText = private_decrypt(pair.getPrivate(), encryptedText, "RSA");
    System.out.printf("Plaintext: %s\n", new String(decryptedText));

    System.out.println();

    // sign message
    System.out.println("Signing with SHA256withRSA...");
    signature = sign(pair.getPrivate(), plainText, "SHA256withRSA");
    System.out.printf("Signature:\n%s\n", new String(signature));

    // verify message
    System.out.println("Verifying with SHA256withRSA...");
    verified = verify(pair.getPublic(), plainText, signature, "SHA256withRSA");
    System.out.printf("Signature verified: %b\n", verified);

    System.out.println();

    System.out.println("Done.");
  }
}