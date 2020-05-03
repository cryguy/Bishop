import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

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
        return (bn_size*6) + (point_size*2) + 1;
    }



}
