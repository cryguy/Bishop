package my.ditto.bishop;

import com.google.gson.Gson;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;


public class kFrag {

    static final byte NO_KEY = (byte) 0;
    static final byte DELEGATING_ONLY = (byte) 1;
    static final byte RECEIVING_ONLY = (byte) 2;
    static final byte DELEGATING_AND_RECEIVING = (byte) 3;

    byte[] identifier;
    BigInteger bn_key;
    ECPoint point_commitment;
    ECPublicKey point_precursor;
    byte[] signature_for_proxy;
    byte[] signature_for_bob;
    byte key_in_signature;


 public kFrag(String json, ECParameterSpec params) throws GeneralSecurityException {
        Gson gson = new Gson();
        var jsonData = gson.fromJson(json, TreeMap.class);

        this.point_commitment = params.getCurve().decodePoint(Base64.decode((String) jsonData.get("point_commitment")));
        this.point_precursor = Helpers.getPublicKey(params.getCurve().decodePoint(Base64.decode((String) jsonData.get("point_precursor"))));
        this.identifier = Base64.decode((String) jsonData.get("identifier"));
        this.bn_key = new BigInteger(Base64.decode((String) jsonData.get("bn_key")));

        this.signature_for_bob = Base64.decode((String) jsonData.get("signature_for_bob"));
        this.signature_for_proxy = Base64.decode((String) jsonData.get("signature_for_proxy"));
        this.key_in_signature = Base64.decode((String) jsonData.get("key_in_signature"))[0];
    }

    // re-keygen
    public static ArrayList<kFrag> generate_kFrag(ECPrivateKey delegating_privateKey, EdDSAPrivateKey signer, ECPublicKey receiving_pubkey, int threshold, int N, byte[] metadata) throws GeneralSecurityException, IOException {
        return generate_kFrag(delegating_privateKey, receiving_pubkey, threshold, N, signer, true, true, metadata);
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
        //System.out.println("PUBKEY : " + Helpers.bytesToHex(bob_pubkey_point.getEncoded(true)));
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

        BigInteger inverse_d = d.modInverse(new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989"));
        coefficients.add(Helpers.multiply(delegating_privkey.getD(), inverse_d, new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")));

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
                        RandomOracle.getStringHash("X_COORDINATE"),
                        kfrag_id},
                params
        );


        BigInteger rk = Helpers.poly_eval(coefficients.toArray(new BigInteger[0]), share_index, new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989"));

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
            mode = DELEGATING_AND_RECEIVING;
        else if (sign_delegating)
            mode = DELEGATING_ONLY;
        else if (sign_receiving)
            mode = RECEIVING_ONLY;
        else
            mode = NO_KEY;

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

    public String toJson() {
        Gson gson = new Gson();

        Map<String, String> jsonData = new TreeMap<>() {{
            put("point_commitment", new String(Base64.encode(point_commitment.getEncoded(true))));
            put("bn_key", new String(Base64.encode(bn_key.toByteArray())));
            put("identifier", new String(Base64.encode(identifier)));
            put("point_precursor", new String(Base64.encode(point_precursor.getQ().getEncoded(true))));
            put("signature_for_proxy", new String(Base64.encode(signature_for_proxy)));
            put("signature_for_bob", new String(Base64.encode(signature_for_bob)));
            put("key_in_signature", new String(Base64.encode(new byte[]{key_in_signature})));
        }};

        return gson.toJson(jsonData, TreeMap.class);
    }


    public kFrag(byte[] identifier, BigInteger bn_key, ECPoint point_commitment, ECPublicKey point_precursor, byte[] signature_for_proxy, byte[] signature_for_bob, byte key_in_signature) {
        this.identifier = identifier;
        this.bn_key = bn_key;
        this.point_commitment = point_commitment;
        this.point_precursor = point_precursor;
        this.signature_for_proxy = signature_for_proxy;
        this.signature_for_bob = signature_for_bob;
        this.key_in_signature = key_in_signature;
    }

    boolean verify(EdDSAPublicKey signing_pubkey, ECPublicKey delegating_pubkey, ECPublicKey receiving_pubkey, ECParameterSpec params, byte[] metadata) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        ECPoint u = RandomOracle.unsafeHash2Point(params.getG().getEncoded(true), "NuCypher/UmbralParameters/u".getBytes(), params);

        boolean correct_commitment = this.point_commitment.equals(u.multiply(this.bn_key));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(this.identifier);
        outputStream.write(this.point_commitment.getEncoded(true));
        outputStream.write(this.point_precursor.getEncoded());
        outputStream.write(this.key_in_signature);

        if (delegating_key_in_sig())
            outputStream.write(delegating_pubkey.getEncoded());
        if (receiving_key_in_sig())
            outputStream.write(receiving_pubkey.getEncoded());
        if (metadata != null) {
            outputStream.write(metadata);
        }

        Signature edDsaSigner = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
        edDsaSigner.initVerify(signing_pubkey);
        edDsaSigner.update(outputStream.toByteArray());
        boolean valid_kfrag = edDsaSigner.verify(signature_for_proxy);

        return valid_kfrag && correct_commitment;
    }

    public boolean verify_for_capsule(Capsule capsule) throws GeneralSecurityException, IOException {
        return verify(capsule.verifying, capsule.correctness_key.get("delegating"), capsule.correctness_key.get("receiving"), capsule.params, capsule.getMetadata());
    }

    boolean delegating_key_in_sig() {
        return key_in_signature == DELEGATING_ONLY || key_in_signature == DELEGATING_AND_RECEIVING;
    }

    boolean receiving_key_in_sig() {
        return key_in_signature == RECEIVING_ONLY || key_in_signature == DELEGATING_AND_RECEIVING;
    }

}
