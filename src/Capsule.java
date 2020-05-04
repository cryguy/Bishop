import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;

public class Capsule {

    ECParameterSpec params;
    ECPoint point_e;
    ECPoint point_v;
    BigInteger signaure;
    HashMap<String, ECPublicKey> correctness_key;
    ArrayList<cFrag> _attached_cfag = new ArrayList<>();
    public Capsule(ECParameterSpec params, ECPoint point_e, ECPoint point_v, BigInteger signaure) {
        this.params = params;
        this.point_e = point_e;
        this.point_v = point_v;
        this.signaure = signaure;
    }

    public byte[] get_bytes() throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(this.point_e.getEncoded(true));
        output.write(this.point_v.getEncoded(true));
        output.write(this.signaure.toByteArray());
        return output.toByteArray();
    }
}
