import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

public class Helpers {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    static byte[] intToBytes( final int i ,final int length) {
        ByteBuffer bb = ByteBuffer.allocate(length);
        bb.putInt(i);
        return bb.array();
    }

    static String bytesToHex(byte[] bytes) {
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

    static ECPrivateKey getPrivateKey(BigInteger secret, ECParameterSpec ecSpec) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(secret, ecSpec);
            return (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    //keygen
    static ECPrivateKey getRandomPrivateKey() {
        Security.addProvider(new BouncyCastleProvider());
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        SecureRandom secureRandom = new SecureRandom();
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters ecParams = new ECDomainParameters(ecSpec.getCurve(), ecSpec.getG(),
                ecSpec.getN(), ecSpec.getH());
        ECKeyGenerationParameters keyGenParam = new ECKeyGenerationParameters(ecParams, secureRandom);
        gen.init(keyGenParam);
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) kp.getPrivate();
        return getPrivateKey(privateKey.getD(), ecSpec);
    }

    static ECPublicKey getPublicKey(ECPrivateKey privateKey) throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleProvider());

        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

        ECPoint Q = ecSpec.getG().multiply(privateKey.getD());
        byte[] publicDerBytes = Q.getEncoded(false);

        ECPoint point = ecSpec.getCurve().decodePoint(publicDerBytes);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
        return (ECPublicKey) keyFactory.generatePublic(pubSpec);

    }


    static BigInteger div(BigInteger a, BigInteger b, BigInteger curve) {
        BigInteger inverse = b.modInverse(curve);
        return a.multiply(inverse).mod(curve);
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
