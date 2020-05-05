import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;


public class kFrag {

    // TODO: serializing
    static final byte NO_KEY = (byte) 0;
    static final byte DELEGATING_ONLY = (byte) 1;
    static final byte RECEIVING_ONLY = (byte) 2;
    static final byte DELEGATING_AND_RECEIVING = (byte) 3;

    byte[] identifier;
    BigInteger bn_key;
    ECPoint point_commitment;
    ECPoint point_precursor;
    byte[] signature_for_proxy;
    byte[] signature_for_bob;
    byte key_in_signature;

    public kFrag(byte[] identifier, BigInteger bn_key, ECPoint point_commitment, ECPoint point_precursor, byte[] signature_for_proxy, byte[] signature_for_bob) {
        this(identifier,bn_key,point_commitment,point_precursor,signature_for_proxy,signature_for_bob,DELEGATING_AND_RECEIVING);
    }

    public kFrag(byte[] identifier, BigInteger bn_key, ECPoint point_commitment, ECPoint point_precursor, byte[] signature_for_proxy, byte[] signature_for_bob, byte key_in_signature) {
        this.identifier = identifier;
        this.bn_key = bn_key;
        this.point_commitment = point_commitment;
        this.point_precursor = point_precursor;
        this.signature_for_proxy = signature_for_proxy;
        this.signature_for_bob = signature_for_bob;
        this.key_in_signature = key_in_signature;
    }

    public static int expected_byte_length(ECPoint curve){
        int bn_size = curve.getCurve().getOrder().bitLength();
        int point_size = curve.getEncoded(true).length;

        //        self.id --> 1 bn_size
        //        self.bn_key --> 1 bn_size
        //        self.point_commitment --> 1 point_size
        //        self.point_precursor --> 1 point_size
        //        self.signature_for_proxy --> 2 bn_size
        //        self.signature_for_bob --> 2 bn_size
        //        self.keys_in_signature --> 1
        return (bn_size * 6) + (point_size * 2) + 1;
    }

    private boolean verify(ECPublicKey signing_pubkey, ECPublicKey delegating_pubkey, ECPublicKey receiving_pubkey, ECParameterSpec params) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        ECPoint u = RandomOracle.unsafeHash2Point(params.getG().getEncoded(true), "NuCypher/UmbralParameters/u".getBytes(), params);

        boolean correct_commitment = this.point_commitment.equals(u.multiply(this.bn_key));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(this.identifier);
        outputStream.write(this.point_commitment.getEncoded(true));
        outputStream.write(this.point_precursor.getEncoded(true));
        outputStream.write(this.key_in_signature);

        if (delegating_key_in_sig())
            outputStream.write(delegating_pubkey.getEncoded());
        if (receiving_key_in_sig())
            outputStream.write(receiving_pubkey.getEncoded());
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initVerify(signing_pubkey);

        ecdsaSign.update(outputStream.toByteArray());
        boolean valid_kfrag = ecdsaSign.verify(signature_for_proxy);

        return valid_kfrag && correct_commitment;
    }

    public boolean verify_for_capsule(Capsule capsule) throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException, IOException {
        return verify(capsule.correctness_key.get("verifying"), capsule.correctness_key.get("delegating"), capsule.correctness_key.get("receiving"), Helpers.getRandomPrivateKey().getParameters());
    }

    boolean delegating_key_in_sig() {
        return key_in_signature == DELEGATING_ONLY || key_in_signature == DELEGATING_AND_RECEIVING;
    }

    boolean receiving_key_in_sig() {
        return key_in_signature == RECEIVING_ONLY || key_in_signature == DELEGATING_AND_RECEIVING;
    }

}
