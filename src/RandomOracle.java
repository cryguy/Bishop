import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import ove.crypto.digest.Blake2b;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class RandomOracle {
    public static byte[] getStringHash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] messageDigest = md.digest(input.getBytes());

        return Arrays.copyOfRange(messageDigest, 0, 8);
    }

    static ECPoint unsafeHash2Point(byte[] data, byte[] label, ECParameterSpec param) {

        // god... this is tedious
        // the following implements len(data).to_bytes(4, 'big')
        // this is gonna be a memory hog if the gc is not ran
        byte[] len_data_temp =  new byte[]{(byte)data.length};
        byte[] len_data = new byte[4];
        int lenappend = 4-len_data_temp.length;
        System.arraycopy(new byte[lenappend], 0, len_data, 0, lenappend);
        System.arraycopy(len_data_temp, 0, len_data, lenappend, len_data_temp.length);

        byte[] len_label_temp =  new byte[]{(byte)label.length};
        byte[] len_label = new byte[4];
        lenappend = 4-len_label_temp.length;
        System.arraycopy(new byte[lenappend], 0, len_label, 0, lenappend);
        System.arraycopy(len_label_temp, 0, len_label, lenappend, len_label_temp.length);

        // same thing as above...
        // label_data = len_label + label + len_data + data
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        try {
            output.write(len_label);
            output.write(label);
            output.write(len_data);
            output.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte[] label_data = output.toByteArray();
        // internal 32 bit counter as additional input
        int i = 0;
        while (i < (2^32)){
            byte[] idata_temp =  new byte[]{(byte)i};
            byte[] idata = new byte[4];
            int idata_append = 4-idata_temp.length;
            System.arraycopy(new byte[idata_append], 0, idata, 0, idata_append);
            System.arraycopy(idata_temp, 0, idata, idata_append, idata_temp.length);
            Blake2b blake2b = Blake2b.Digest.newInstance();
            // do stupid initialization...
            {
                // all 64 byte with 0
                byte[] first_update = new byte[64];
                blake2b.update(first_update);
            }

            ByteArrayOutputStream label_idata = new ByteArrayOutputStream();

            try {
                label_idata.write(label_data);
                label_idata.write(idata);
            } catch (IOException e) {
                e.printStackTrace();
            }

            byte[] to_digest = label_idata.toByteArray();
            blake2b.update(to_digest);
            byte[] hash_digest = Arrays.copyOfRange(blake2b.digest(), 0, 33); // copy 32 bytes , this might need to be changed to accommodate other curves

            byte sign;
            if (hash_digest[0] != (byte)1)
                sign = (byte)2;
            else
                sign = (byte)3;

            ByteArrayOutputStream comp_point = new ByteArrayOutputStream();
            try {
                comp_point.write(sign);
                comp_point.write(Arrays.copyOfRange(hash_digest, 1, hash_digest.length));
            } catch (IOException e) {
                e.printStackTrace();
            }

            byte[] compressed_point = comp_point.toByteArray();
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

    /*
        Blake2b and get resulting hash inside selected curve
         */
    static BigInteger hash2curve(byte[][] items_to_hash, ECParameterSpec parameters) throws GeneralSecurityException {
        Blake2b blake2b = Blake2b.Digest.newInstance();
        // just following what is in the original implementation... which is dumb dumb...
        {
            // i spent 2 days here...
            // the magic string is "hash_to_curvebn"
            // and when done with all the stuff, update once more with sha512("NON_INTERACTIVE")
            byte[] stupid_constant = Helpers.hexStringToByteArray("686173685f746f5f6375727665626e");
            byte[] first_update = new byte[64];
            int b = 0;
            for (byte i : stupid_constant) {
                first_update[b++] = i; // should use some other copy method... this is just me being lazy
            }
            blake2b.update(first_update);
        }
        for (byte[] key : items_to_hash) {
            blake2b.update(key);
        }

        byte[] hash = blake2b.digest();
        BigInteger hash_digest = new BigInteger(Helpers.bytesToHex(hash), 16); // somehow if using the raw bytes here, some numbers will overflow to 0 causing the rest of the steps to be wrong
        if (hash_digest.signum() != 1) {
            throw new GeneralSecurityException("hash_digest is negative");
        }
//        System.out.println("hash_digest = " + hash_digest);
//        System.out.println("hash_digest_hex = " + Helpers.bytesToHex(hash));

        BigInteger one = new BigInteger("1");
        BigInteger order_minus_one = parameters.getCurve().getOrder().subtract(one);
        BigInteger[] divrem = hash_digest.divideAndRemainder(order_minus_one);

        //        System.out.println("finalresult_hex - " + Helpers.bytesToHex(hashfinal.toByteArray()));
        return hash_digest.mod(order_minus_one).add(one); // not with curve... beware!! , might break
    }
}
