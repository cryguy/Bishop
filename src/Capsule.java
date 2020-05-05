import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;

public class Capsule {
    // TODO: From Bytes
    ECParameterSpec params;
    ECPoint point_e;
    ECPoint point_v;
    BigInteger signaure;
    HashMap<String, ECPublicKey> correctness_key = new HashMap<>();
    ArrayList<cFrag> _attached_cfag = new ArrayList<>();

    public Capsule(ECParameterSpec params, ECPoint point_e, ECPoint point_v, BigInteger signaure) {
        this.params = params;
        this.point_e = point_e;
        this.point_v = point_v;
        this.signaure = signaure;
    }

    public cFrag first_cfrag() throws GeneralSecurityException {
        if (_attached_cfag.isEmpty())
            throw new GeneralSecurityException("No Cfrags attached yet!");
        return _attached_cfag.get(0);
    }

    public void set_correctness_key(ECPublicKey alice_public, ECPublicKey bob_public, ECPublicKey alice_verifying) {
        this.correctness_key.put("delegating", alice_public);
        this.correctness_key.put("receiving", bob_public);
        this.correctness_key.put("verifying", alice_verifying);
    }

    public void attach_cfrag(cFrag cfrag) throws GeneralSecurityException, IOException {
        if (cfrag.verify_correctness(this))
            this._attached_cfag.add(cfrag);
        else
            throw new SecurityException("cFrag is not correct! Cant be attached");
    }

    public boolean not_valid() throws GeneralSecurityException {
        /*
        g = self.params.g
        e, v, s = self.components()
        h = hash_to_curvebn(e, v, params=self.params)\
        g * s == v + (h * e)
         */
        BigInteger h = RandomOracle.hash2curve(new byte[][]{point_e.getEncoded(true), point_v.getEncoded(true)}, params);
        return !params.getG().multiply(signaure).equals(point_v.add(point_e.multiply(h)));
    }

    public byte[] get_bytes() throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(this.point_e.getEncoded(true));
        output.write(this.point_v.getEncoded(true));
        output.write(this.signaure.toByteArray());
        return output.toByteArray();
    }
}
