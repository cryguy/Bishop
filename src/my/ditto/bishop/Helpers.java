package my.ditto.bishop;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.PrimitiveIterator;

public class Helpers {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    static byte[] intToBytes( final int i ,final int length) {
        ByteBuffer bb = ByteBuffer.allocate(length);
        bb.putInt(i);
        return bb.array();
    }

    static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    static ECPrivateKey getPrivateKey(BigInteger secret, ECParameterSpec ecSpec) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(secret, ecSpec);
        return (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }

    static int[] to_mnemonic(byte[] data) throws GeneralSecurityException {

        StringBuilder data_bin = new StringBuilder();
        for (byte datum : data) {
            data_bin.append(String.format("%8s", Integer.toBinaryString(datum & 0xFF)).replace(' ', '0'));
        }

        var datarecur = data_bin.toString();
        var length = ((data.length * 8) / 11) + 1;
        int it = 0;
        int j = 0;
        StringBuilder stringBuilder = new StringBuilder();
        String[] accum = new String[length + 1];
        var lengthlast = 0;
        for (PrimitiveIterator.OfInt iter = datarecur.chars().iterator(); iter.hasNext(); ) {
            int i = iter.next();
            if (it == 11) {
                accum[j] = stringBuilder.toString();
                stringBuilder = new StringBuilder();
                it = 0;
                if (i == 49)
                    stringBuilder.append(1);
                if (i == 48)
                    stringBuilder.append(0);
                it++;
                j++;
            } else if (iter.hasNext()) {
                if (i == 49)
                    stringBuilder.append(1);
                if (i == 48)
                    stringBuilder.append(0);
                it++;
            } else {
                // not reliable...
                if (i == 49)
                    stringBuilder.append(1);
                if (i == 48)
                    stringBuilder.append(0);
                accum[j] = stringBuilder.toString();
                lengthlast = stringBuilder.toString().length();
            }

        }
        // to fix the last byte
        accum[length] = "11111111000";
        int[] returning = new int[length + 2];
        for (int i = 0; i < accum.length; i++) {

            int foo = Integer.parseInt(accum[i], 2);
            if (foo > 2040)
                throw new GeneralSecurityException("Refresh Code from PC. -  Error"); // lazy fix
            returning[i] = foo;
        }
        // how many bytes to copy to the left
        returning[returning.length - 1] = lengthlast;

        return returning;
    }

    static byte[] from_mneumonic(int[] data) {

        StringBuilder data_bin = new StringBuilder();
        for (int i = 0; i < data.length - 1; i++) {
            if (i != data.length - 1)
                data_bin.append(String.format("%11s", Integer.toBinaryString(data[i])).replace(' ', '0'));
            else
                data_bin.append(Integer.toBinaryString(data[i])); // last byte stays the same
        }

        // 11 from the right
        // take 3
        // 11 + x
        // last byte of original
        String original = data_bin.substring(data_bin.length() - (11 + data[data.length - 1]), data_bin.length() - 11);
        // restore last byte and remove the padding
        data_bin.replace(data_bin.length() - 22, data_bin.length(), original);
        // reconstruct byte array
        int it = 0;
        byte[] from_mne = new byte[data_bin.toString().length() / 8];
        int j = 0;
        StringBuilder stringBuilder = new StringBuilder();
        for (PrimitiveIterator.OfInt iter = data_bin.toString().chars().iterator(); iter.hasNext(); ) {
            int i = iter.next();
            if (i == 49)
                stringBuilder.append(1);
            if (i == 48)
                stringBuilder.append(0);

            if (it != 7) {
                it++;
            } else {
                from_mne[j++] = (byte) Integer.parseInt(stringBuilder.toString(), 2);
                stringBuilder = new StringBuilder();
                it = 0;
            }
        }
        return from_mne;
    }

    //keygen
    static ECPrivateKey getRandomPrivateKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        X9ECParameters curveParams = CustomNamedCurves.getByName("Curve25519");
        ECParameterSpec ecSpec = new ECParameterSpec(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        kpg.initialize(ecSpec);

        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        return (ECPrivateKey) privateKey;

    }

    static byte[] doECDH(ECPrivateKey privatekey, ECPublicKey publicKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(privatekey);
        ka.doPhase(publicKey, true);
        return ka.generateSecret();
    }

    static ECPublicKey getPublicKey(ECPrivateKey privateKey) throws GeneralSecurityException {

//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        X9ECParameters curveParams = CustomNamedCurves.getByName("Curve25519");
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        ECParameterSpec pubSpec = new ECParameterSpec(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(curveParams.getG().multiply(privateKey.getD()), pubSpec);
        return (ECPublicKey) kf.generatePublic(publicKeySpec);

    }


    static BigInteger div(BigInteger a, BigInteger b, BigInteger curve) {
        BigInteger inverse = b.modInverse(curve);
        return a.multiply(inverse).mod(curve);
    }

    static BigInteger multiply(BigInteger a, BigInteger b, BigInteger curve) {
        return a.multiply(b).mod(curve);
    }

    static BigInteger addition(BigInteger a, BigInteger b, BigInteger curve) {
        return a.add(b).mod(curve);
    }

    static BigInteger poly_eval(BigInteger[] coeff, BigInteger x, BigInteger mod) {
        BigInteger result = coeff[coeff.length - 1];

        for (int i = 2; i < coeff.length + 1; i++) {
            //result = result.multiply(x).mod(mod).add(coeff[coeff.length-i]).mod(mod);
            // result = (result * x) + coeff[i]

            result = addition(multiply(result, x, mod), coeff[coeff.length - i], mod);
        }
        return result;
    }


    static BigInteger lambda_coeff(BigInteger id_i, BigInteger[] selected_ids, ECParameterSpec params) {
        ArrayList<BigInteger> ids = new ArrayList<>();
        for (BigInteger selected_id : selected_ids) {
            if (!selected_id.equals(id_i))
                ids.add(selected_id);
        }

        if (ids.isEmpty())
            return new BigInteger("1");
        // modular arithmetic
        // subtraction = subtracts b from a modulo order
        // addition = add a and b modulo order
        // true division = ( b modInverse order multiplied by a ) modulo order = a/b
        // result = ids[0] * inverse( (ids[0] - id_i) mod order ) mod order
        BigInteger result = div(ids.get(0), ids.get(0).subtract(id_i).mod(params.getCurve().getOrder()), params.getCurve().getOrder());

        for (int i = 1; i < ids.size(); i++) {
            result = result.multiply(div(ids.get(i), ids.get(i).subtract(id_i).mod(params.getCurve().getOrder()), params.getCurve().getOrder())).mod(params.getCurve().getOrder());
        }
        return result;
    }
}
