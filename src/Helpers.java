import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

public class Helpers {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

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

    static String deriveCurveName(org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec) throws GeneralSecurityException {
        for (@SuppressWarnings("rawtypes")
             Enumeration names = ECNamedCurveTable.getNames(); names.hasMoreElements();){
            final String name = (String)names.nextElement();

            final ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(name);

            if (params.getN().equals(ecParameterSpec.getN())
                    && params.getH().equals(ecParameterSpec.getH())
                    && params.getCurve().equals(ecParameterSpec.getCurve())
                    && params.getG().equals(ecParameterSpec.getG())){
                return name;
            }
        }

        throw new GeneralSecurityException("Could not find name for curve");
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

    static ECPublicKey getPublicKey(ECPrivateKey privateKey) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

            ECPoint Q = ecSpec.getG().multiply(privateKey.getD());
            byte[] publicDerBytes = Q.getEncoded(false);

            ECPoint point = ecSpec.getCurve().decodePoint(publicDerBytes);
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
            return (ECPublicKey) keyFactory.generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }
}
