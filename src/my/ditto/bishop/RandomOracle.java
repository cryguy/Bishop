package my.ditto.bishop;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import ove.crypto.digest.Blake2b;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class RandomOracle {
    public static byte[] getStringHash(String input) throws NoSuchAlgorithmException {
        if (input == null) {
            return null;
        }
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] messageDigest = md.digest(input.getBytes());

        return Arrays.copyOfRange(messageDigest, 0, 8);
    }

    public static byte[] chacha20_poly1305_enc(byte[] nounce, byte[] data, byte[] key, byte[] additional) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        // init ChaCha20-Poly1305
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding");
        AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(nounce);
        SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
        // insert Authenticated Data
        if (additional != null) {
            cipher.updateAAD(additional);
        }

        byte[] cipher_text = cipher.doFinal(data);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(nounce);
        output.write(cipher_text);
        return output.toByteArray();
    }

    public static byte[] chacha20_poly1305_dec(byte[] data, byte[] key, byte[] aditional) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding");
        byte[] iv = Arrays.copyOfRange(data, 0, 12);
        byte[] cipher_text = Arrays.copyOfRange(data, 12, data.length);
        AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
        if (aditional != null) {
            cipher.updateAAD(aditional);
        }
        return cipher.doFinal(cipher_text);
    }

    static byte[] kdf(byte[] data, int key_length, byte[] salt, byte[] info) {

        HKDFParameters params = new HKDFParameters(data, salt, info);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new Blake2bDigest());
        hkdf.init(params);
        byte[] output = new byte[key_length];
        hkdf.generateBytes(output, 0, key_length);
        return output;
    }

    // TODO: add customization options
    /*
        Blake2b and get resulting hash inside selected curve
     */
    static BigInteger hash2curve(byte[][] items_to_hash, ECParameterSpec parameters) throws GeneralSecurityException {
        // using blake2b as our hashing algorithm
        // the following first_update is the "personalization" used by pyumbral.
        Blake2b blake2b = Blake2b.Digest.newInstance();
        // just following what is in the original implementation... which is dumb dumb...
        // should add customization options.
        {
            // i spent 2 days here...
            // the magic string is "hash_to_curvebn" + padding till its 64 bytes
            // and when done with all the stuff, update once more with sha512("NON_INTERACTIVE")
            // sacrificing 20-30ms here for readability
            byte[] stupid_constant = Helpers.hexStringToByteArray(String.format("%-128s", "686173685F746F5F6375727665626E").replace(' ', '0'));

            blake2b.update(stupid_constant);
        }
        for (int i = 0; i < items_to_hash.length; i++) {
            if (items_to_hash[i] != null) {
                blake2b.update(items_to_hash[i]);
            }
        }

        byte[] hash = blake2b.digest();

        BigInteger hash_digest = new BigInteger(Helpers.bytesToHex(hash), 16); // somehow if using the raw bytes here, some numbers will overflow to 0 causing the rest of the steps to be wrong

        if (hash_digest.signum() != 1) {
            throw new GeneralSecurityException("hash_digest is negative");
        }

        BigInteger one = new BigInteger("1");
        BigInteger order_minus_one = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989").subtract(one);

        return hash_digest.mod(order_minus_one).add(one); // not with curve... beware!! , might break
    }

    static ECPoint unsafeHash2Point(byte[] data, byte[] label, ECParameterSpec param) throws IOException {

        byte[] len_data = Helpers.intToBytes(data.length, 4);

        byte[] len_label = Helpers.intToBytes(label.length, 4);

        // label_data = len_label + label + len_data + data
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        {
            output.write(len_label);
            output.write(label);
            output.write(len_data);
            output.write(data);
        }

        byte[] label_data = output.toByteArray();
        output.reset();
        // internal 32 bit counter as additional input
        int i = 0;
        while (i < (2 ^ 32)) {

            byte[] idata = Helpers.intToBytes(i, 4);

            Blake2b blake2b = Blake2b.Digest.newInstance();
            // why did i do this???
            // ans : this is to be the same as pyUmbral - might change this... can cause privacy issues
            /*
            def __init__(self, customization_string: bytes = b''):

                if len(customization_string) > Hash.CUSTOMIZATION_STRING_LENGTH:
                    raise ValueError("The maximum length of the customization string is "
                                     "{} bytes".format(Hash.CUSTOMIZATION_STRING_LENGTH))

                self.customization_string = customization_string.ljust(
                    Hash.CUSTOMIZATION_STRING_LENGTH,
                    Hash.CUSTOMIZATION_STRING_PAD
                )
                self.update(self.customization_string)
             */
            // do stupid initialization...
            {
                byte[] first_update = new byte[64];
                blake2b.update(first_update);
            }

            output.write(label_data);
            output.write(idata);


            blake2b.update(output.toByteArray());
            output.reset();
            byte[] hash_digest = Arrays.copyOfRange(blake2b.digest(), 0, 33); // copy 33 bytes, this will be in public key format

            byte sign;
            if (hash_digest[0] != (byte) 1)
                sign = (byte) 2;
            else
                sign = (byte) 3;

            output.write(sign);
            output.write(Arrays.copyOfRange(hash_digest, 1, hash_digest.length));

            byte[] compressed_point = output.toByteArray();

            output.reset();
            try {
                return param.getCurve().decodePoint(compressed_point);
            } catch (IllegalArgumentException ignore) {
                // the point is not in the curve...
            }
            i++;
        }
        // probability of hitting this is 2^-32
        throw new SecurityException("Could not hash input to curve");
    }

}
