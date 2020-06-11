package my.ditto.bishop;

import com.google.gson.Gson;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.*;

public class Capsule {
    byte[] metadata = null;
    ECParameterSpec params;
    ECPoint point_e;
    ECPoint point_v;
    BigInteger signaure;
    byte[] hash;
    EdDSAPublicKey verifying = null;
    HashMap<String, ECPublicKey> correctness_key = new HashMap<>();
    ArrayList<cFrag> _attached_cfag = new ArrayList<>();

    public Capsule(String json, ECParameterSpec params) {
        Gson gson = new Gson();
        TreeMap jsonData = gson.fromJson(json, TreeMap.class);
        this.params = params;
        this.point_e = params.getCurve().decodePoint(Base64.decode((String) jsonData.get("point_e")));
        this.point_v = params.getCurve().decodePoint(Base64.decode((String) jsonData.get("point_v")));
        this.signaure = new BigInteger(Base64.decode((String) jsonData.get("signature")));
        if (jsonData.containsKey("metadata"))
            this.metadata = Base64.decode((String) jsonData.get("metadata"));
        this.hash = Base64.decode((String) jsonData.get("hash"));
    }

    public String toJson() {
        Gson gson = new Gson();
        // maybe revert to byte[], less overhead?
        // why Base64? less Data to send... easier to handle as a string
        Map<String, String> jsonData = new TreeMap<>() {{
            //put("point_e", point_e.getEncoded(true));
            put("point_e", new String(Base64.encode(point_e.getEncoded(true))));
            put("point_v", new String(Base64.encode(point_v.getEncoded(true))));
            put("signature", new String(Base64.encode(signaure.toByteArray())));
            put("hash", new String(Base64.encode(hash)));
        }};
        if (metadata != null) {
            jsonData.put("metadata", new String(Base64.encode(metadata)));
        }
        return gson.toJson(jsonData, TreeMap.class);
    }

    public Capsule(ECParameterSpec params, ECPoint point_e, ECPoint point_v, BigInteger signaure, byte[] metadata, byte[] hash) {
        this.params = params;
        this.point_e = point_e;
        this.point_v = point_v;
        this.signaure = signaure;
        this.metadata = metadata;
        this.hash = hash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Capsule capsule = (Capsule) o;

        if (!Arrays.equals(metadata, capsule.metadata)) return false;
        if (!params.equals(capsule.params)) return false;
        if (!point_e.equals(capsule.point_e)) return false;
        if (!point_v.equals(capsule.point_v)) return false;
        if (!signaure.equals(capsule.signaure)) return false;
        if (!Arrays.equals(hash, capsule.hash)) return false;
        if (verifying != null ? !verifying.equals(capsule.verifying) : capsule.verifying != null) return false;
        if (correctness_key != null ? !correctness_key.equals(capsule.correctness_key) : capsule.correctness_key != null)
            return false;
        return _attached_cfag != null ? _attached_cfag.equals(capsule._attached_cfag) : capsule._attached_cfag == null;
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(metadata);
        result = 31 * result + params.hashCode();
        result = 31 * result + point_e.hashCode();
        result = 31 * result + point_v.hashCode();
        result = 31 * result + signaure.hashCode();
        result = 31 * result + Arrays.hashCode(hash);
        return result;
    }

    public cFrag first_cfrag() throws GeneralSecurityException {
        if (_attached_cfag.isEmpty())
            throw new GeneralSecurityException("No Cfrags attached yet!");
        return _attached_cfag.get(0);
    }

    public void set_correctness_key(ECPublicKey alice_public, ECPublicKey bob_public, EdDSAPublicKey alice_verifying) {
        this.correctness_key.put("delegating", alice_public);
        this.correctness_key.put("receiving", bob_public);
        verifying = alice_verifying;
    }

    public void attach_cfrag(cFrag cfrag) throws GeneralSecurityException, IOException {
        if (cfrag.verify_correctness(this))
            this._attached_cfag.add(cfrag);
        else
            throw new GeneralSecurityException("cFrag is not correct! Cant be attached");
    }

    public boolean not_valid() throws GeneralSecurityException, IOException {
        /*
        g = self.params.g
        e, v, s = self.components()
        h = hash_to_curvebn(e, v, params=self.params)\
        g * s == v + (h * e)
         */
        BigInteger h = RandomOracle.hash2curve(new byte[][]{point_e.getEncoded(true), point_v.getEncoded(true)}, params);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(this.point_e.getEncoded(true));
        outputStream.write(this.point_v.getEncoded(true));


        var hash = RandomOracle.kdf(outputStream.toByteArray(), 32, signaure.toByteArray(), metadata);

        return !(params.getG().multiply(signaure).equals(point_v.add(point_e.multiply(h))) && Arrays.equals(hash, this.hash));
    }

    public byte[] get_bytes() throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(this.point_e.getEncoded(true));
        output.write(this.point_v.getEncoded(true));
        output.write(this.signaure.toByteArray());
        if (this.metadata != null) {
            output.write(this.metadata);
        }
        return output.toByteArray();
    }
}
