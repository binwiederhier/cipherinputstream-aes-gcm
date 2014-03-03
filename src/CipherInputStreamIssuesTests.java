// This code belongs to the blog post "CipherInputStream for AEAD modes is broken in JDK7 (GCM, EAX, etc.)"

// http://blog.philippheckel.com/2014/03/01/cipherinputstream-for-aead-modes-is-broken-in-jdk7-gcm/
// March 2014, Philipp C. Heckel

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

public class CipherInputStreamIssuesTests {
	private static final SecureRandom secureRandom = new SecureRandom();
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static void main(String args[]) throws Exception {
		System.out.println("----------------------------------------------------------------------------------");

		testA_JavaxCipherWithAesGcm();
		testB_JavaxCipherInputStreamWithAesGcm();
		testC_JavaxCipherInputStreamWithAesGcmFixed();
		testD_BouncyCastleCipherInputStreamWithAesGcm();
		testE_BouncyCastleCipherInputStreamWithAesGcmLongPlaintext();
		testF_BouncyCastleFixedCipherInputStreamWithAesGcmLongPlaintextNoTampering();
		testG_BouncyCastleFixedCipherInputStreamWithAesGcmLongPlaintextAndTampering();

		System.out.println("----------------------------------------------------------------------------------");
	}
	
	public static void testA_JavaxCipherWithAesGcm() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = "Confirm 100$ pay".getBytes("ASCII"); 		
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Attack / alter ciphertext (an attacker would do this!) 
		byte[] alteredCiphertext = Arrays.clone(originalCiphertext);		
		alteredCiphertext[8] = (byte) (alteredCiphertext[8] ^ 0x08); // <<< Change 100$ to 900$			
		
		// Decrypt with regular CipherInputStream (from JDK6/7)
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(randomKey, "AES"), new IvParameterSpec(randomIv));
		
		try {
			cipher.doFinal(alteredCiphertext);		
			//  ^^^^^^ INTERESTING PART ^^^^^^	
			//
			//  The GCM implementation in BouncyCastle and the Cipher class in the javax.crypto package 
			//  behave correctly: A BadPaddingException is thrown when we try to decrypt the altered ciphertext.
			//  The code below is not executed.
			//
			
			System.out.println("Test A: javac.crypto.Cipher:                                 NOT OK, tampering not detected");
		}
		catch (BadPaddingException e) {		
			System.out.println("Test A: javac.crypto.Cipher:                                 OK, tampering detected");
		}
	}	
	
	public static void testB_JavaxCipherInputStreamWithAesGcm() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = "Confirm 100$ pay".getBytes("ASCII"); 		
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Attack / alter ciphertext (an attacker would do this!) 
		byte[] alteredCiphertext = Arrays.clone(originalCiphertext);		
		alteredCiphertext[8] = (byte) (alteredCiphertext[8] ^ 0x08); // <<< Change 100$ to 900$			
		
		// Decrypt with regular CipherInputStream (from JDK6/7)
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(randomKey, "AES"), new IvParameterSpec(randomIv));
		
		try {
			byte[] decryptedPlaintext = readFromStream(new javax.crypto.CipherInputStream(new ByteArrayInputStream(alteredCiphertext), cipher));
			//                                         ^^^^^^^^ INTERESTING PART ^^^^^^^^	
			//
			//  The regular CipherInputStream in the javax.crypto package simply ignores BadPaddingExceptions
			//  and doesn't pass them to the application. Tampering with the ciphertext does thereby not throw  
			//  a MAC verification error. The code below is actually executed. The two plaintexts do not match!
			//  The decrypted payload is "Confirm 900$ pay" (not: "Confirm 100$ pay")
			//

			System.out.println("Test B: javac.crypto.CipherInputStream:                      NOT OK, tampering not detected");
			System.out.println("        - Original plaintext:                                - " + new String(originalPlaintext, "ASCII"));
			System.out.println("        - Decrypted plaintext:                               - " + new String(decryptedPlaintext, "ASCII"));
		}
		catch (Exception e) {
			System.out.println("Test B: javac.crypto.CipherInputStream:                      OK, tampering detected");
		}
	}	

	public static void testC_JavaxCipherInputStreamWithAesGcmFixed() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException,
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = "Confirm 100$ pay".getBytes("ASCII"); 	
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Attack / alter ciphertext (an attacker would do this!) 
		byte[] alteredCiphertext = Arrays.clone(originalCiphertext);		
		alteredCiphertext[8] = (byte) (alteredCiphertext[8] ^ 0x08); // <<< Change 100$ to 900$
		
		// Decrypt with "fixed" JDK implementation of CipherInputStream
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(randomKey, "AES"), new IvParameterSpec(randomIv));
		
		try {
			readFromStream(new QuickFixDemoCipherInputStream(new ByteArrayInputStream(alteredCiphertext), cipher));		
			//             ^^^^^^^ INTERESTING PART ^^^^^^^^	
			//
			//  When Cipher.doFinal() is called in the QuickFixDemoCipherInputStream, a BadPaddingException
			//  is thrown and passed to the application wrapped in a InvalidCiphertextIOException (inner 
			//  class in QuickFixDemoCipherInputStream). This way, MAC verification errors can be detected. 
			//  The code below is not executed.
			//
			
			System.out.println("Test C: QuickFixDemoCipherInputStream:                       NOT OK, tampering not detected");				
		}
		catch (QuickFixDemoCipherInputStream.QuickFixDemoInvalidCipherTextIOException e) {
			System.out.println("Test C: QuickFixDemoCipherInputStream:                       OK, tampering detected");				
		}
	}
	
	public static void testD_BouncyCastleCipherInputStreamWithAesGcm() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = "Confirm 100$ pay".getBytes("ASCII"); 	
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Attack / alter ciphertext (an attacker would do this!) 
		byte[] alteredCiphertext = Arrays.clone(originalCiphertext);		
		alteredCiphertext[8] = (byte) (alteredCiphertext[8] ^ 0x08); // <<< Change 100$ to 900$
		
		// Decrypt with BouncyCastle implementation of CipherInputStream
		AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine()); 
		cipher.init(false, new AEADParameters(new KeyParameter(randomKey), 128, randomIv));
		
		try {
			readFromStream(new org.bouncycastle.crypto.io.CipherInputStream(new ByteArrayInputStream(alteredCiphertext), cipher));
			//             ^^^^^^^^^^^^^^^ INTERESTING PART ^^^^^^^^^^^^^^^^	
			//
			//  The BouncyCastle implementation of the CipherInputStream detects MAC verification errors and
			//  throws a InvalidCipherTextIOException if an error occurs. Nice! A more or less minor issue
			//  however is that it is incompatible with the standard JCE Cipher class from the javax.crypto 
			//  package. The new interface AEADBlockCipher must be used. The code below is not executed.		

			System.out.println("Test D: org.bouncycastle.crypto.io.CipherInputStream:        NOT OK, tampering not detected");						
		}
		catch (InvalidCipherTextIOException e) {
			System.out.println("Test D: org.bouncycastle.crypto.io.CipherInputStream:        OK, tampering detected");						
		}
	}
	
	public static void testE_BouncyCastleCipherInputStreamWithAesGcmLongPlaintext() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = createRandomArray(4080); // <<<< 4080 bytes fails, 4079 bytes works! 	
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Decrypt with BouncyCastle implementation of CipherInputStream
		AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine()); 
		cipher.init(false, new AEADParameters(new KeyParameter(randomKey), 128, randomIv));
		
		try {
			readFromStream(new org.bouncycastle.crypto.io.CipherInputStream(new ByteArrayInputStream(originalCiphertext), cipher));
			//             ^^^^^^^^^^^^^^^ INTERESTING PART ^^^^^^^^^^^^^^^^	
			//
			//  In this example, the BouncyCastle implementation of the CipherInputStream throws an ArrayIndexOutOfBoundsException.
			//  The only difference to the example above is that the plaintext is now 4080 bytes long! For 4079 bytes plaintexts,
			//  everything works just fine.

			System.out.println("Test E: org.bouncycastle.crypto.io.CipherInputStream:        OK, throws no exception");						
		}
		catch (IOException e) {
			System.out.println("Test E: org.bouncycastle.crypto.io.CipherInputStream:        NOT OK throws: "+e.getMessage());
		}
	}	
	
	public static void testF_BouncyCastleFixedCipherInputStreamWithAesGcmLongPlaintextNoTampering() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = createRandomArray(4080); // <<<< 4080 bytes fails, 4079 bytes works! 	
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Decrypt with BouncyCastle implementation of CipherInputStream
		AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine()); 
		cipher.init(false, new AEADParameters(new KeyParameter(randomKey), 128, randomIv));
		
		try {
			byte[] decryptedPlaintext = readFromStream(new BcFixedCipherInputStream(new ByteArrayInputStream(originalCiphertext), cipher));
			//             ^^^^^^^^^^^^^^^ INTERESTING PART ^^^^^^^^^^^^^^^^	
			//
			//  In this example, the BouncyCastle implementation of the CipherInputStream throws an ArrayIndexOutOfBoundsException.
			//  The only difference to the example above is that the plaintext is now 4080 bytes long! For 4079 bytes plaintexts,
			//  everything works just fine.

			if (!Arrays.areEqual(originalPlaintext, decryptedPlaintext)) {
				System.out.println("Test F: Fixed org.bouncycastle.crypto.io.CipherInputStream:  NOT OK, original plaintext does not match.");
			}
			else {
				System.out.println("Test F: Fixed org.bouncycastle.crypto.io.CipherInputStream:  OK, throws no exception");
			}
		}
		catch (IOException e) {
			System.out.println("Test F: Fixed org.bouncycastle.crypto.io.CipherInputStream:  NOT OK, throws: "+e.getMessage());
		}
	}	 
	
	public static void testG_BouncyCastleFixedCipherInputStreamWithAesGcmLongPlaintextAndTampering() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = createRandomArray(4080); // <<<< 4080 bytes fails, 4079 bytes works! 	
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Attack / alter ciphertext (an attacker would do this!) 
		byte[] alteredCiphertext = Arrays.clone(originalCiphertext);		
		alteredCiphertext[8] = (byte) (alteredCiphertext[8] ^ 0x08); // <<< Change 100$ to 900$		
		
		// Decrypt with BouncyCastle implementation of CipherInputStream
		AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine()); 
		cipher.init(false, new AEADParameters(new KeyParameter(randomKey), 128, randomIv));
		
		try {
			readFromStream(new BcFixedCipherInputStream(new ByteArrayInputStream(alteredCiphertext), cipher));
			//             ^^^^^^^^^^^^^^^ INTERESTING PART ^^^^^^^^^^^^^^^^	
			//
			//  In this example, the the BouncyCastle implementation of 1.50 (will be updated in 1.51) of the 
			//  CipherInputStream is used. It fixes the ArrayIndexOutOfBoundsException and now works also
			//  for longer plaintexts. The code below is not executed.

			System.out.println("Test G: Fixed org.bouncycastle.crypto.io.CipherInputStream:  NOT OK, tampering not detected");						
		}
		catch (InvalidCipherTextIOException e) {
			System.out.println("Test G: Fixed org.bouncycastle.crypto.io.CipherInputStream:  OK, tampering detected");
		}
	}	

	private static byte[] readFromStream(InputStream inputStream) throws IOException {
		ByteArrayOutputStream decryptedPlaintextOutputStream = new ByteArrayOutputStream(); 
		
		int read = -1;
		byte[] buffer = new byte[16];
		
		while (-1 != (read = inputStream.read(buffer))) {
			decryptedPlaintextOutputStream.write(buffer, 0, read);
		}
		
		inputStream.close();
		decryptedPlaintextOutputStream.close();
		
		return decryptedPlaintextOutputStream.toByteArray();  		
	}
	
	private static byte[] encryptWithAesGcm(byte[] plaintext, byte[] randomKeyBytes, byte[] randomIvBytes) throws IOException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {

		SecretKey randomKey = new SecretKeySpec(randomKeyBytes, "AES");
		
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, randomKey, new IvParameterSpec(randomIvBytes));
		
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher);
		
		cipherOutputStream.write(plaintext);
		cipherOutputStream.close();
		
		return byteArrayOutputStream.toByteArray();
	}
	
	private static byte[] createRandomArray(int size) {
		byte[] randomByteArray = new byte[size];
		secureRandom.nextBytes(randomByteArray);

		return randomByteArray;
	}	
}

