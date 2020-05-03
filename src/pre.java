import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.logging.Logger;

public class pre {
    private final static Logger LOGGER = Logger.getLogger(pre.class.getName());

    // re-keygen
    public static ArrayList<kFrag> generate_kfrag(ECPrivateKey delegating_privkey, ECPublicKey receiving_pubkey, int threshold, int N, ECPrivateKey signer) throws GeneralSecurityException, IOException {
        return generate_kfrag(delegating_privkey,receiving_pubkey,threshold,N,signer,true,true);
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
            coefficients.add(Helpers.getRandomPrivateKey().getD())
;        }

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
