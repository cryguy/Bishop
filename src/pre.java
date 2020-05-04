import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.logging.Logger;

public class pre {
    private final static Logger LOGGER = Logger.getLogger(pre.class.getName());

    // re-keygen
    public static ArrayList<kFrag> generate_kfrag(ECPrivateKey delegating_privkey, ECPublicKey receiving_pubkey, int threshold, int N, ECPrivateKey signer) throws GeneralSecurityException, IOException {
        return generate_kfrag(delegating_privkey, receiving_pubkey, threshold, N, signer, true, true);
    }

    public static SimpleEntry<byte[], Capsule> _encapsulate(ECPublicKey alice_pub, int length) throws GeneralSecurityException {

        ECParameterSpec params = alice_pub.getParameters();
        ECPoint g = params.getG();

        BigInteger r = Helpers.getRandomPrivateKey().getD();
        ECPoint pub_r = g.multiply(r);

        BigInteger u = Helpers.getRandomPrivateKey().getD();
        ECPoint pub_u = g.multiply(u);

        BigInteger h = RandomOracle.hash2curve(new byte[][]{pub_r.getEncoded(true), pub_u.getEncoded(true)}, params);

        BigInteger s = u.add(r.multiply(h).mod(params.getCurve().getOrder())).mod(params.getCurve().getOrder());

        ECPoint shared = alice_pub.getQ().multiply(r.add(u).mod(params.getCurve().getOrder()));

        byte[] key = RandomOracle.kdf(shared.getEncoded(true), length, null, null);

        Capsule capsule = new Capsule(params, pub_r, pub_u, s);
        //return key, Capsule(point_e=pub_r, point_v=pub_u, bn_sig=s, params=params)
        return new SimpleEntry<>(key, capsule);
    }

    // TODO: Make a reencrypt function? or is this done serverside...

    public static SimpleEntry<byte[], Capsule> encrypt(ECPublicKey publicKey, byte[] plaintext) throws GeneralSecurityException, IOException {
        SimpleEntry<byte[], Capsule> key_cap = _encapsulate(publicKey, 32);
        byte[] key = key_cap.getKey();
        Capsule capsule = key_cap.getValue();

        byte[] capsule_bytes = capsule.get_bytes();

        // perform chacha-poly1305
        byte[] nounce = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nounce);
        byte[] ciphertext = RandomOracle.chacha20_poly1305_enc(nounce, plaintext, key, capsule_bytes);
        return new SimpleEntry<>(ciphertext, capsule);
    }

    private static byte[] _decap_reencrypted(ECPrivateKey receiving, Capsule capsule, int key_length) {
        /*
            params = capsule.params

            pub_key = receiving_privkey.get_pubkey().point_key
            priv_key = receiving_privkey.bn_key

            precursor = capsule.first_cfrag().point_precursor
            dh_point = priv_key * precursor

            # Combination of CFrags via Shamir's Secret Sharing reconstruction
            xs = list()
            for cfrag in capsule._attached_cfrags:
                x = hash_to_curvebn(precursor,
                                    pub_key,
                                    dh_point,
                                    bytes(constants.X_COORDINATE),
                                    cfrag.kfrag_id,
                                    params=params)
                xs.append(x)

            e_summands, v_summands = list(), list()
            for cfrag, x in zip(capsule._attached_cfrags, xs):
                if precursor != cfrag.point_precursor:
                    raise ValueError("Attached CFrags are not pairwise consistent")
                lambda_i = lambda_coeff(x, xs)
                e_summands.append(lambda_i * cfrag.point_e1)
                v_summands.append(lambda_i * cfrag.point_v1)

            e_prime = sum(e_summands[1:], e_summands[0])
            v_prime = sum(v_summands[1:], v_summands[0])

            # Secret value 'd' allows to make Umbral non-interactive
            d = hash_to_curvebn(precursor,
                                pub_key,
                                dh_point,
                                bytes(constants.NON_INTERACTIVE),
                                params=params)

            e, v, s = capsule.components()
            h = hash_to_curvebn(e, v, params=params)

            orig_pub_key = capsule.get_correctness_keys()['delegating'].point_key  # type: ignore

            if not (s / d) * orig_pub_key == (h * e_prime) + v_prime:
                // not enuf cfrag...

            shared_key = d * (e_prime + v_prime)
            encapsulated_key = kdf(shared_key, key_length)
            return encapsulated_key
         */
        return null;
    }

    public static byte[] decrypt(byte[] cipher_text, Capsule capsule, ECPrivateKey decryption_key, boolean check_proof) throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] key = new byte[0];
        if (capsule._attached_cfag.size() != 0)
            // implement decryption for Bob
            ;
        else {
            // decryption for alice
            byte[] shared_key = capsule.point_e.add(capsule.point_v).multiply(decryption_key.getD()).getEncoded(true);
            key = RandomOracle.kdf(shared_key, 32, null, null);
        }

        return RandomOracle.chacha20_poly1305_dec(cipher_text, key, capsule.get_bytes());
    }

    public static ArrayList<kFrag> generate_kfrag(ECPrivateKey delegating_privkey, ECPublicKey receiving_pubkey, int threshold, int N, ECPrivateKey signer, boolean sign_delegating, boolean sign_receiving) throws GeneralSecurityException, IOException {

        if (threshold <= 0 || threshold > N)
            throw new IllegalArgumentException("Arguments threshold and N must satisfy 0 < threshold <= N");
        if (!receiving_pubkey.getParameters().getG().equals(delegating_privkey.getParameters().getG()))
            throw new IllegalArgumentException("Keys must have the same parameter set.");

        ECParameterSpec params = delegating_privkey.getParameters();
        ECPoint g = params.getG();
        ECPublicKey delegating_pubkey = Helpers.getPublicKey(delegating_privkey);
        ECPoint bob_pubkey_point = receiving_pubkey.getQ();

        // generate a new key
        ECPrivateKey precursorPrivate = Helpers.getRandomPrivateKey();

        assert precursorPrivate != null;
        // compute XA = g^xA
        ECPoint precursor = g.multiply(precursorPrivate.getD());
        // compute shared dh key
        ECPoint dh_point = bob_pubkey_point.multiply(precursorPrivate.getD());
        byte[][] input_d = {precursor.getEncoded(true),bob_pubkey_point.getEncoded(true), dh_point.getEncoded(true), RandomOracle.getStringHash("NON_INTERACTIVE")};
        BigInteger d = RandomOracle.hash2curve(input_d, precursorPrivate.getParameters());

        ArrayList<BigInteger> coefficients = new ArrayList<>();
        coefficients.add(delegating_privkey.getD().multiply(d.modInverse(params.getCurve().getOrder())).mod(params.getCurve().getOrder()));

        for (int i = 0; i < threshold-1; i++) {
            coefficients.add(Helpers.getRandomPrivateKey().getD());
        }

        ArrayList<kFrag> kfrags = new ArrayList<>();
        SecureRandom random = new SecureRandom(); // may switch this out...

        // do Shamir Secret Sharing here
        for (int i = 0; i < N; i++) {
            byte[] kfrag_id = new byte[32];
            random.nextBytes(kfrag_id);

            // share_index = hash_to_curvebn(precursor,
            //                              bob_pubkey_point,
            //                              dh_point,
            //                              bytes(constants.X_COORDINATE),
            //                              kfrag_id,
            //                              params=params)

            BigInteger share_index = RandomOracle.hash2curve(
                    new byte[][]{precursor.getEncoded(true),
                    bob_pubkey_point.getEncoded(true),
                    dh_point.getEncoded(true),
                    RandomOracle.getStringHash("X_COORDINATE"), kfrag_id },
                    params
            );


            // The re-encryption key share is the result of evaluating the generating
            // polynomial for the index value
            /*

                result = coeff[-1]
                for i in range(-2, -len(coeff) - 1, -1):
                    result = (result * x) + coeff[i]
                return result
             */
            // if size is 5
            /*
            j should be
            -2,-3,-4,-5
             */
            BigInteger rk = coefficients.get(coefficients.size()-1);
            for(int j=-2; j > (((coefficients.size())*-1)-1) ; j--)
            {
                rk = (rk.multiply(share_index).mod(params.getCurve().getOrder())).add(coefficients.get(coefficients.size()+j));
            }

            ECPoint commitment = RandomOracle.unsafeHash2Point(params.getG().getEncoded(true),"NuCypher/UmbralParameters/u".getBytes(), params).multiply(rk);

            ByteArrayOutputStream sign_bob = new ByteArrayOutputStream();
            try {
                sign_bob.write(kfrag_id);
                assert delegating_pubkey != null;
                sign_bob.write(delegating_pubkey.getEncoded());
                sign_bob.write(receiving_pubkey.getEncoded());
                sign_bob.write(commitment.getEncoded(true));
                sign_bob.write(precursor.getEncoded(true));
            } catch (IOException e) {
                e.printStackTrace();
            }
            // sign message for bob
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaSign.initSign(signer);

            ecdsaSign.update(sign_bob.toByteArray());
            byte[] signature_for_bob = ecdsaSign.sign();

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
            try {
                sign_proxy.write(kfrag_id);
                sign_proxy.write(commitment.getEncoded(true));
                sign_proxy.write(precursor.getEncoded(true));
                sign_proxy.write(mode);
                if (sign_delegating) {
                    assert delegating_pubkey != null;
                    sign_proxy.write(delegating_pubkey.getEncoded());
                }
                if (sign_receiving)
                    sign_proxy.write(receiving_pubkey.getEncoded());
            } catch (IOException e) {
                e.printStackTrace();
            }

            ecdsaSign.update(sign_bob.toByteArray());
            byte[] signature_for_proxy = ecdsaSign.sign();

            kfrags.add(new kFrag(kfrag_id,rk,commitment,precursor,signature_for_proxy,signature_for_bob,mode));
        }
        return kfrags;
    }
}
