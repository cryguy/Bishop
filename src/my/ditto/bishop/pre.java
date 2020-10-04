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

    // re-keygen
    public static ArrayList<kFrag> generate_kFrag(ECPrivateKey delegating_privateKey, EdDSAPrivateKey signer, ECPublicKey receiving_pubkey, int threshold, int N, byte[] metadata) throws GeneralSecurityException, IOException {
        return generate_kFrag(delegating_privateKey, receiving_pubkey, threshold, N, signer, true, true, metadata);
    }

    public static SimpleEntry<byte[], Capsule> _encapsulate(ECPublicKey alice_pub, int length, byte[] metadata) throws GeneralSecurityException, IOException {

        ECParameterSpec params = alice_pub.getParameters();
        ECPoint g = params.getG();

        BigInteger r = Helpers.getRandomPrivateKey().getD();
        ECPoint pub_r = g.multiply(r);

        BigInteger u = Helpers.getRandomPrivateKey().getD();

        ECPoint pub_u = g.multiply(u);

        BigInteger h = RandomOracle.hash2curve(new byte[][]{pub_r.getEncoded(true), pub_u.getEncoded(true)}, params);

        BigInteger s = u.add(r.multiply(h).mod(params.getCurve().getOrder())).mod(params.getCurve().getOrder());


        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(pub_r.getEncoded(true));
        outputStream.write(pub_u.getEncoded(true));


        var hash = RandomOracle.kdf(outputStream.toByteArray(), 32, s.toByteArray(), metadata);


        outputStream.reset();
        ECPoint shared = alice_pub.getQ().multiply(r.add(u).mod(params.getCurve().getOrder()));

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
        return decapsulateReencrypted(receiving, capsule, 32, capsule.metadata);
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

        if (!original_pub.multiply(Helpers.div(s, d, params.getCurve().getOrder())).equals(v_prime.add(e_prime.multiply(h))))
            throw new GeneralSecurityException("Failed to get key, not enough kfrags");

        ECPoint shared_key = e_prime.add(v_prime).multiply(d);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(shared_key.getEncoded(true));
        if (metadata != null) {
            outputStream.write(metadata);
        }
        return RandomOracle.kdf(outputStream.toByteArray(), key_length, null, null);
    }

    public static cFrag reencrypt(kFrag kfrag, Capsule capsule, boolean provide_proof, byte[] proxy_meta, boolean verify_kfrag) throws GeneralSecurityException, IOException {
        if (capsule.not_valid())
            throw new GeneralSecurityException("my.ditto.bishop.Capsule Verification Failed. my.ditto.bishop.Capsule tampered.");
        if (verify_kfrag)
            // wtf happened here...
            // it didnt work before this
            if (!kfrag.verify_for_capsule(capsule))
                throw new GeneralSecurityException("Invalid kFrag!");

        BigInteger rk = kfrag.bn_key;

        ECPoint e1 = capsule.point_e.multiply(rk);
        ECPoint v1 = capsule.point_v.multiply(rk);

        cFrag cfrag = new cFrag(e1, v1, kfrag.identifier, kfrag.point_precursor);

        if (provide_proof) {
            cfrag.proof_correctness(capsule, kfrag, proxy_meta);
        }
        return cfrag;
    }

    public static byte[] decrypt(byte[] cipher_text, Capsule capsule, ECPrivateKey decryption_key, boolean check_proof) throws IOException, GeneralSecurityException {
        byte[] key;
        if (capsule.not_valid())
            throw new GeneralSecurityException("Capsule Verification Failed. Capsule tampered.");

//        if (capsule._attached_cfag.size() != 0)
//            key = _open_capsule(decryption_key, capsule, true);
//        else {
//            // decryption for alice
//            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//            outputStream.write(capsule.point_e.add(capsule.point_v).multiply(decryption_key.getD()).getEncoded(true));
//            if (capsule.metadata != null) {
//                outputStream.write(capsule.metadata);
//            }
//            key = RandomOracle.kdf(outputStream.toByteArray(), 32, null, null);
//        }
        // try to open capsule
        // option 2, doesnt leak as much info? doesnt matter that much i guess
        try {
            key = _open_capsule(decryption_key, capsule, check_proof);
        } catch (GeneralSecurityException e) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(capsule.point_e.add(capsule.point_v).multiply(decryption_key.getD()).getEncoded(true));
            if (capsule.metadata != null) {
                outputStream.write(capsule.metadata);
            }
            key = RandomOracle.kdf(outputStream.toByteArray(), 32, null, null);
        }
        return RandomOracle.chacha20_poly1305_dec(cipher_text, key, capsule.get_bytes());
    }

    // verified this part
    public static ArrayList<kFrag> generate_kFrag(ECPrivateKey delegating_privkey, ECPublicKey receiving_pubkey, int threshold, int N, EdDSAPrivateKey signer, boolean sign_delegating, boolean sign_receiving, byte[] metadata) throws GeneralSecurityException, IOException {

        if (threshold <= 0 || threshold > N)
            throw new IllegalArgumentException("Arguments threshold and N must satisfy 0 < threshold <= N");
        if (!receiving_pubkey.getParameters().getG().equals(delegating_privkey.getParameters().getG()))
            throw new IllegalArgumentException("Keys must have the same parameter set.");

        ECParameterSpec params = delegating_privkey.getParameters();
        ECPublicKey delegating_pubkey = Helpers.getPublicKey(delegating_privkey);
        ECPoint bob_pubkey_point = receiving_pubkey.getQ();

        // generate a new key
        ECPrivateKey precursorPrivate = Helpers.getRandomPrivateKey();


        assert precursorPrivate != null;
        // compute XA = g^xA
        //ECPoint precursor = g.multiply(precursorPrivate.getD());
        ECPublicKey precursor = Helpers.getPublicKey(precursorPrivate);
        // compute shared dh key

        // ECPoint dh_point = bob_pubkey_point.multiply(precursorPrivate.getD());
        var dh = Helpers.doECDH(precursorPrivate, receiving_pubkey);
        byte[][] input_d = {precursor.getEncoded(), bob_pubkey_point.getEncoded(true), dh, RandomOracle.getStringHash("NON_INTERACTIVE"), RandomOracle.getStringHash(Helpers.bytesToHex(metadata))};
        BigInteger d = RandomOracle.hash2curve(input_d, precursorPrivate.getParameters());

        ArrayList<BigInteger> coefficients = new ArrayList<>();

        BigInteger inverse_d = d.modInverse(params.getCurve().getOrder());
        coefficients.add(Helpers.multiply(delegating_privkey.getD(), inverse_d, params.getCurve().getOrder()));

        for (int i = 0; i < threshold - 1; i++) {
            coefficients.add(Helpers.getRandomPrivateKey().getD());
        }

        ArrayList<kFrag> kfrags = new ArrayList<>();
        SecureRandom random = new SecureRandom(); // may switch this out...

        // do Shamir Secret Sharing here
        for (int i = 0; i < N; i++) {
            byte[] kfrag_id = new byte[32];
            random.nextBytes(kfrag_id);
            // tested bellow...
            kFrag kfrag = getkFrag(receiving_pubkey, signer, sign_delegating, sign_receiving, params, delegating_pubkey, bob_pubkey_point, precursor, dh, coefficients, kfrag_id, metadata);
            kfrags.add(kfrag);
        }
        return kfrags;
    }

    private static kFrag getkFrag(ECPublicKey receiving_pubkey, EdDSAPrivateKey signer, boolean sign_delegating, boolean sign_receiving, ECParameterSpec params, ECPublicKey delegating_pubkey, ECPoint bob_pubkey_point, ECPublicKey precursor, byte[] dh, ArrayList<BigInteger> coefficients, byte[] kfrag_id, byte[] metadata) throws GeneralSecurityException, IOException {

        BigInteger share_index = RandomOracle.hash2curve(
                new byte[][]{precursor.getEncoded(),
                        bob_pubkey_point.getEncoded(true),
                        dh,
                        RandomOracle.getStringHash("X_COORDINATE"), kfrag_id},
                params
        );


        BigInteger rk = Helpers.poly_eval(coefficients.toArray(new BigInteger[0]), share_index, params.getCurve().getOrder());

        ECPoint commitment = RandomOracle.unsafeHash2Point(params.getG().getEncoded(true), "NuCypher/UmbralParameters/u".getBytes(), params).multiply(rk);

        ByteArrayOutputStream sign_bob = new ByteArrayOutputStream();

        sign_bob.write(kfrag_id);
        assert delegating_pubkey != null;
        sign_bob.write(delegating_pubkey.getEncoded());
        sign_bob.write(receiving_pubkey.getEncoded());
        sign_bob.write(commitment.getEncoded(true));
        sign_bob.write(precursor.getEncoded());

        if (metadata != null) {
            sign_bob.write(metadata);
        }
        // sign message for bob

        Signature edDsaSigner = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
        edDsaSigner.initSign(signer);
        edDsaSigner.update(sign_bob.toByteArray());

        byte[] signature_for_bob = edDsaSigner.sign();

        byte mode;
        if (sign_delegating && sign_receiving)
            mode = kFrag.DELEGATING_AND_RECEIVING;
        else if (sign_delegating)
            mode = kFrag.DELEGATING_ONLY;
        else if (sign_receiving)
            mode = kFrag.RECEIVING_ONLY;
        else
            mode = kFrag.NO_KEY;

        ByteArrayOutputStream sign_proxy = new ByteArrayOutputStream();
        sign_proxy.write(kfrag_id);
        sign_proxy.write(commitment.getEncoded(true));
        sign_proxy.write(precursor.getEncoded());
        sign_proxy.write(mode);
        if (sign_delegating) {
            sign_proxy.write(delegating_pubkey.getEncoded());
        }
        if (sign_receiving)
            sign_proxy.write(receiving_pubkey.getEncoded());
        if (metadata != null) {
            sign_proxy.write(metadata);
        }
        edDsaSigner.update(sign_proxy.toByteArray());
        byte[] signature_for_proxy = edDsaSigner.sign();

        return new kFrag(kfrag_id, rk, commitment, precursor, signature_for_proxy, signature_for_bob, mode);
    }
}
