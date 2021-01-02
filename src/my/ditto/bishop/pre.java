package my.ditto.bishop;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.logging.Logger;

public class pre {
    private final static Logger LOGGER = Logger.getLogger(pre.class.getName());

    public static SimpleEntry<byte[], Capsule> _encapsulate(ECPublicKey alice_pub, int length, byte[] metadata) throws GeneralSecurityException, IOException {

        ECParameterSpec params = alice_pub.getParameters();
        ECPoint g = params.getG();

        BigInteger r = Helpers.getRandomPrivateKey().getD();
        ECPoint pub_r = g.multiply(r);

        BigInteger u = Helpers.getRandomPrivateKey().getD();

        ECPoint pub_u = g.multiply(u);

        BigInteger h = RandomOracle.hash2curve(new byte[][]{pub_r.getEncoded(true), pub_u.getEncoded(true)}, params);

        BigInteger s = u.add(r.multiply(h).mod(new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989"))).mod(new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989"));


        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(pub_r.getEncoded(true));
        outputStream.write(pub_u.getEncoded(true));


        var hash = RandomOracle.kdf(outputStream.toByteArray(), 32, s.toByteArray(), metadata);


        outputStream.reset();
        ECPoint shared = alice_pub.getQ().multiply(r.add(u).mod(new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")));

        outputStream.write(shared.getEncoded(true));
        if (metadata != null) {
            outputStream.write(metadata);
        }
        byte[] key = RandomOracle.kdf(outputStream.toByteArray(), length, null, null);

        Capsule capsule = new Capsule(params, pub_r, pub_u, s, metadata, hash);
        //return key, my.ditto.bishop.Capsule(point_e=pub_r, point_v=pub_u, bn_sig=s, params=params)
        return new SimpleEntry<>(key, capsule);
    }

    public static SimpleEntry<byte[], Capsule> encrypt(ECPublicKey publicKey, byte[] plaintext, byte[] metadata) throws GeneralSecurityException, IOException {
        SimpleEntry<byte[], Capsule> key_cap = _encapsulate(publicKey, 32, metadata);
        byte[] key = key_cap.getKey();
        Capsule capsule = key_cap.getValue();

        byte[] capsule_bytes = capsule.get_bytes();

        byte[] nonce = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
        byte[] ciphertext = RandomOracle.chacha20_poly1305_enc(nonce, plaintext, key, capsule_bytes);
        return new SimpleEntry<>(ciphertext, capsule);
    }

    private static byte[] _open_capsule(ECPrivateKey receiving, Capsule capsule, boolean check_proof) throws GeneralSecurityException, IOException {
        if (check_proof) {
            ArrayList<cFrag> bad_cfrag = new ArrayList<>();
            for (cFrag cfrag : capsule._attached_cfag) {
                if (!cfrag.verify_correctness(capsule))
                    bad_cfrag.add(cfrag);
            }
            if (bad_cfrag.size() != 0) {
                throw new SecurityException("Some cFrags are invalid");
            }
        }
        return decapsulateReencrypted(receiving, capsule, 32, capsule.getMetadata());
    }

    private static byte[] decapsulateReencrypted(ECPrivateKey receiving, Capsule capsule, int key_length, byte[] metadata) throws GeneralSecurityException, IOException {
        ECParameterSpec params = capsule.params;
        ECPoint publicKey = Helpers.getPublicKey(receiving).getQ();

        ECPublicKey precursor = capsule.first_cfrag().precursor;
        var dh = Helpers.doECDH(receiving, precursor);

        //ECPoint dh_point = precursor.multiply(privateKey);
        ArrayList<BigInteger> xs = new ArrayList<>();

        for (cFrag cFrag : capsule._attached_cfag) {
            xs.add(RandomOracle.hash2curve(
                    new byte[][]{precursor.getEncoded(),
                            publicKey.getEncoded(true),
                            dh,
                            RandomOracle.getStringHash("X_COORDINATE"),
                            cFrag.kfrag_id},
                    params));
        }


        ArrayList<ECPoint> e_sum = new ArrayList<>();
        ArrayList<ECPoint> v_sum = new ArrayList<>();

        for (int i = 0; i < xs.size(); i++) {
            cFrag cfrag = capsule._attached_cfag.get(i);
            BigInteger x = xs.get(i);
            if (!precursor.equals(cfrag.precursor))
                throw new GeneralSecurityException("Attached CFrags not pairwise consistent");
            BigInteger lambda_i = Helpers.lambda_coeff(x, xs.toArray(new BigInteger[0]), params);

            e_sum.add(cfrag.e1.multiply(lambda_i));
            v_sum.add(cfrag.v1.multiply(lambda_i));
        }

        ECPoint e_prime = e_sum.get(0);
        ECPoint v_prime = v_sum.get(0);
        for (int j = 1; j < e_sum.size(); j++) {
            e_prime = e_prime.add(e_sum.get(j));
            v_prime = v_prime.add(v_sum.get(j));
        }
        //System.out.println("EPRIME - " + Helpers.bytesToHex(e_prime.getEncoded(true)));
        //System.out.println("VPRIME - " + Helpers.bytesToHex(v_prime.getEncoded(true)));
        BigInteger d = RandomOracle.hash2curve(new byte[][]{precursor.getEncoded(),
                        publicKey.getEncoded(true),
                        dh,
                        RandomOracle.getStringHash("NON_INTERACTIVE"),
                        RandomOracle.getStringHash(Helpers.bytesToHex(metadata))
                }
                , params);

        ECPoint e = capsule.point_e;
        ECPoint v = capsule.point_v;
        BigInteger s = capsule.signaure;
        BigInteger h = RandomOracle.hash2curve(new byte[][]{e.getEncoded(true), v.getEncoded(true)}, params);

        ECPoint original_pub = capsule.correctness_key.get("delegating").getQ();

        if (!original_pub.multiply(Helpers.div(s, d, new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989"))).equals(v_prime.add(e_prime.multiply(h))))
            throw new GeneralSecurityException("Failed to get key, not enough kfrags");

        ECPoint shared_key = e_prime.add(v_prime).multiply(d);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(shared_key.getEncoded(true));
        if (metadata != null) {
            outputStream.write(metadata);
        }
        return RandomOracle.kdf(outputStream.toByteArray(), key_length, null, null);
    }

    public static byte[] decrypt(byte[] cipher_text, Capsule capsule, ECPrivateKey decryption_key, boolean check_proof) throws IOException, GeneralSecurityException {
        byte[] key;
        if (capsule.not_valid())
            throw new GeneralSecurityException("Capsule Verification Failed. Capsule tampered.");

        try {
            key = _open_capsule(decryption_key, capsule, check_proof);
        } catch (GeneralSecurityException e) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(capsule.point_e.add(capsule.point_v).multiply(decryption_key.getD()).getEncoded(true));
            if (capsule.getMetadata() != null) {
                outputStream.write(capsule.getMetadata());
            }
            key = RandomOracle.kdf(outputStream.toByteArray(), 32, null, null);
        }
        return RandomOracle.chacha20_poly1305_dec(cipher_text, key, capsule.get_bytes());
    }
}
