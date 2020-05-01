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
import ove.crypto.digest.Blake2b;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

public class pre {
    public static byte[] getStringHash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] messageDigest = md.digest(input.getBytes());

        return Arrays.copyOfRange(messageDigest, 0, 8);
    }
    private static String deriveCurveName(org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec) throws GeneralSecurityException{
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
    private final static Logger LOGGER = Logger.getLogger(pre.class.getName());

    /*
    Blake2b and get resulting hash inside selected curve
     */
    static BigInteger hash2curve(byte[][] keys, ECParameterSpec parameters) throws GeneralSecurityException {
        LOGGER.info("[DEBUG] called hash2curve");
        LOGGER.info("[DEBUG] CurveName - " + deriveCurveName(parameters));
        Blake2b blake2b = Blake2b.Digest.newInstance();
        byte[] constant_end = Helpers.hexStringToByteArray("4c591cee9247687d");
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
        for (byte[] key : keys) {
            blake2b.update(key);
        }

        //blake2b.update(constant_end);
        byte[] hash = blake2b.digest();
        BigInteger hash_digest = new BigInteger(Helpers.bytesToHex(hash), 16); // somehow if using the raw bytes here, some numbers will overflow to 0 causing the rest of the steps to be wrong
        if (hash_digest.signum() != 1) {
            LOGGER.severe("[ERROR] hash_digest is negative - ");
            throw new GeneralSecurityException("hash_digest is negative");
        }
        System.out.println("hash_digest = " + hash_digest);
        System.out.println("hash_digest_hex = " + Helpers.bytesToHex(hash));

        BigInteger one = new BigInteger("1");
        BigInteger order_minus_one = parameters.getCurve().getOrder().subtract(one);
        System.out.println("ORDER MINONE - " + order_minus_one);
        System.out.println("ORDER MINONE_HEX - " + Helpers.bytesToHex(order_minus_one.toByteArray()));
        BigInteger[] divrem = hash_digest.divideAndRemainder(order_minus_one);

        BigInteger hashfinal = hash_digest.mod(order_minus_one).add(one);
        System.out.println("finalresult_hex - " + Helpers.bytesToHex(hashfinal.toByteArray()));
        return hashfinal; // not with curve... beware!! , might break
    }

    // re-keygen
    public static ArrayList generate_kfrag(ECPrivateKey delegating_privkey, ECPublicKey receiving_pubkey, int threshold, int N, ECPrivateKey signer) throws GeneralSecurityException {

        if (threshold <= 0 || threshold > N)
            throw new IllegalArgumentException("Arguments threshold and N must satisfy 0 < threshold <= N");
        if (!receiving_pubkey.getParameters().getG().equals(delegating_privkey.getParameters().getG()))
            throw new IllegalArgumentException("Keys must have the same parameter set.");

        ECParameterSpec params = delegating_privkey.getParameters();
        ECPoint g = params.getG();
        ECPublicKey delegating_pubkey = getPublicKey(delegating_privkey);
        ECPoint bob_pubkey_point = receiving_pubkey.getQ();

        // generate a new key
        ECPrivateKey precursorPrivate = getRandomPrivateKey();

        assert precursorPrivate != null;
        // compute XA = g^xA
        ECPoint precursor = g.multiply(precursorPrivate.getD());
        // compute shared dh key
        ECPoint dh_point = bob_pubkey_point.multiply(precursorPrivate.getD());
        byte[][] input_d = {precursor.getEncoded(true),bob_pubkey_point.getEncoded(true), dh_point.getEncoded(true),getStringHash("NON_INTERACTIVE")};
        BigInteger d = hash2curve(input_d, precursorPrivate.getParameters());

        ArrayList<BigInteger> coefficients = new ArrayList<>();
        coefficients.add(delegating_privkey.getD().multiply(d.modInverse(params.getCurve().getOrder())).mod(params.getCurve().getOrder()));

        for (int i = 0; i < threshold-1; i++) {
            coefficients.add(getRandomPrivateKey().getD())
;        }

        ArrayList<kFrag> kfrags = new ArrayList<>();
        SecureRandom random = new SecureRandom(); // may switch this out...

        for (int i = 0; i < N; i++) {
            byte kfrag_id[] = new byte[32];
            random.nextBytes(kfrag_id);

//            share_index = hash_to_curvebn(precursor,
//                    bob_pubkey_point,
//                    dh_point,
//                    bytes(constants.X_COORDINATE),
//                    kfrag_id,
//                    params=params)
            byte[][] inputs = {precursor.getEncoded(true),bob_pubkey_point.getEncoded(true), dh_point.getEncoded(true),getStringHash("X_COORDINATE"), kfrag_id};
            BigInteger share_index = hash2curve(inputs,params);
        }
        return kfrags;
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

    public static void test() throws GeneralSecurityException {
        ECPrivateKey alicePrivate = getRandomPrivateKey();
        assert alicePrivate != null;
        ECPrivateKey bobPrivate = getRandomPrivateKey();
        assert bobPrivate != null;
        System.out.println(alicePrivate.getParameters().getCurve().getOrder().bitLength());
        //generate_kfrag(alicePrivate,getPublicKey(bobPrivate),2,3,null);
        // ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        // System.out.println(privateKey);
        // //System.out.println("Secret BigNum = " + privateKey.getD());
        //System.out.println("public coords = " + publicKey.getQ());
        //System.out.println(bytesToHex(privateKey.getParameters().getG().getEncoded(true)));
        BigInteger aliceBigInt = new BigInteger("43941d9fb0fbbae48838afc7fc2ba23c22bdde8bc18b3d745c7c90dfd34d3aa1", 16);

        ECPoint precursor = alicePrivate.getParameters().getCurve().decodePoint(Helpers.hexStringToByteArray("020b5131dd2ede443030778694ecb9b3c7d787ba82618a982e493097a537dacc26"));
        ECPoint bob_key = alicePrivate.getParameters().getCurve().decodePoint(Helpers.hexStringToByteArray("034c4467526b0f16dbacd7571ca07ace7ab0ed51f7e39dc94a903521193cc5c41f"));
        ECPoint dh_point = alicePrivate.getParameters().getCurve().decodePoint(Helpers.hexStringToByteArray("03659391192b9d61f74adeebf34dcc8982af15a5f296a676740cc8f49dbe1fe4e7"));

        byte[][] input_d = {precursor.getEncoded(true),bob_key.getEncoded(true), dh_point.getEncoded(true),getStringHash("NON_INTERACTIVE")};
        BigInteger blk2b = hash2curve(input_d, alicePrivate.getParameters());
        System.out.println("~d - " + blk2b.modInverse(alicePrivate.getParameters().getCurve().getOrder()).toString(16));
        System.out.println(aliceBigInt.multiply(blk2b.modInverse(alicePrivate.getParameters().getCurve().getOrder())).mod(alicePrivate.getParameters().getCurve().getOrder()).toString(16));

        //BigInteger blk2b = hash2curve(precursor, bob_key, dh_point, alicePrivate.getParameters());
        //System.out.println(blk2b);
        //System.out.println(bytesToHex(blk2b.toByteArray()));
    }


    public static void main(String[] args) throws GeneralSecurityException {
        LOGGER.setLevel(Level.WARNING);
        test();

    }
}
