import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;

public class cFrag {
    ECPoint e1;
    ECPoint v1;
    byte[] kfrag_id;
    ECPublicKey precursor;
    CorrectnessProof proof;

    public cFrag(ECPoint e1, ECPoint v1, byte[] kfrag_id, ECPublicKey precursor) {
        this(e1, v1, kfrag_id, precursor, null);
    }

    public cFrag(ECPoint e1, ECPoint v1, byte[] kfrag_id, ECPublicKey precursor, CorrectnessProof proof) {
        this.e1 = e1;
        this.v1 = v1;
        this.kfrag_id = kfrag_id;
        this.precursor = precursor;
        this.proof = proof;
    }

    public byte[] to_bytes() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(e1.getEncoded(true));
        outputStream.write(v1.getEncoded(true));
        outputStream.write(kfrag_id);
        outputStream.write(precursor.getEncoded());
        if (proof != null)
            outputStream.write(proof.to_bytes());
        return outputStream.toByteArray();
    }

    public void proof_correctness(Capsule capsule, kFrag kfrag, byte[] metadata) throws GeneralSecurityException, IOException {
        ECParameterSpec params = capsule.params;
        if (capsule.not_valid())
            throw new GeneralSecurityException("Capsule Verification Failed. Capsule tampered.");

        BigInteger rk = kfrag.bn_key;
        BigInteger t = Helpers.getRandomPrivateKey().getD();
        ECPoint e = capsule.point_e;
        ECPoint v = capsule.point_v;

        ECPoint e1 = this.e1;
        ECPoint v1 = this.v1;

        ECPoint u = RandomOracle.unsafeHash2Point(params.getG().getEncoded(true), "NuCypher/UmbralParameters/u".getBytes(), params);
        ECPoint u1 = kfrag.point_commitment;

        ECPoint e2 = e.multiply(t);
        ECPoint v2 = v.multiply(t);
        ECPoint u2 = u.multiply(t);

        ArrayList<byte[]> input = new ArrayList<>();

        Collections.addAll(input, e.getEncoded(true), e1.getEncoded(true), e2.getEncoded(true),
                v.getEncoded(true), v1.getEncoded(true), v2.getEncoded(true),
                u.getEncoded(true), u1.getEncoded(true), u2.getEncoded(true));

        if (metadata != null)
            input.add(metadata);

        BigInteger h = RandomOracle.hash2curve(input.toArray(new byte[0][]), params);

        BigInteger z3 = t.add(h.multiply(rk).mod(params.getCurve().getOrder())).mod(params.getCurve().getOrder());

        this.proof = new CorrectnessProof(e2, v2, u1, u2, z3, kfrag.signature_for_bob, metadata);
    }

    public boolean verify_correctness(Capsule capsule) throws GeneralSecurityException, IOException {
        if (proof == null)
            throw new GeneralSecurityException("No Proof Provided");

        HashMap<String, ECPublicKey> correctness_key = capsule.correctness_key;

        ECPublicKey delegating_pubkey = correctness_key.get("delegating");
        Ed25519PublicKeyParameters signing_pubkey = capsule.verifying;
        ECPublicKey receiving_pubkey = correctness_key.get("receiving");

        ECParameterSpec params = capsule.params;

        ECPoint e = capsule.point_e;
        ECPoint v = capsule.point_v;

        ECPoint e1 = this.e1;
        ECPoint v1 = this.v1;

        ECPoint u = RandomOracle.unsafeHash2Point(params.getG().getEncoded(true), "NuCypher/UmbralParameters/u".getBytes(), params);
        ECPoint u1 = proof.commitment;

        ECPoint e2 = proof.e2;
        ECPoint v2 = proof.v2;
        ECPoint u2 = proof.pok;

        ArrayList<byte[]> input = new ArrayList<>();

        Collections.addAll(input, e.getEncoded(true), e1.getEncoded(true), e2.getEncoded(true),
                v.getEncoded(true), v1.getEncoded(true), v2.getEncoded(true),
                u.getEncoded(true), u1.getEncoded(true), u2.getEncoded(true));

        if (proof.metadata != null)
            input.add(proof.metadata);

        BigInteger h = RandomOracle.hash2curve(input.toArray(new byte[0][]), params);

        ECPublicKey precursor = this.precursor;
        byte[] kfrag_id = this.kfrag_id;

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(kfrag_id);
        outputStream.write(delegating_pubkey.getEncoded());
        outputStream.write(receiving_pubkey.getEncoded());
        outputStream.write(u1.getEncoded(true));
        outputStream.write(precursor.getEncoded());

        if (capsule.metadata != null) {
            outputStream.write(capsule.metadata);
        }
        Ed25519Signer ed25519Signer = new Ed25519Signer();
        ed25519Signer.init(false, signing_pubkey);

        ed25519Signer.update(outputStream.toByteArray(), 0, outputStream.toByteArray().length);
        boolean valid_sig = ed25519Signer.verifySignature(this.proof.signature);

        BigInteger z3 = proof.sig_key;
        boolean correct_e = e.multiply(z3).equals(e2.add(e1.multiply(h)));
        boolean correct_v = v.multiply(z3).equals(v2.add(v1.multiply(h)));
        boolean correct_rk_commitment = u.multiply(z3).equals(u2.add(u1.multiply(h)));

        return valid_sig && correct_e && correct_v && correct_rk_commitment;

    }


}
