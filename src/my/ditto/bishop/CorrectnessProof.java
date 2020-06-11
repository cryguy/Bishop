package my.ditto.bishop;

import com.google.gson.Gson;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

public class CorrectnessProof {
    ECPoint e2;
    ECPoint v2;
    ECPoint commitment;
    ECPoint pok;
    BigInteger sig_key;
    byte[] signature;
    byte[] metadata = null;

    public CorrectnessProof(String json, ECParameterSpec params) {
        Gson gson = new Gson();
        var jsonData = gson.fromJson(json, TreeMap.class);

        this.e2 = params.getCurve().decodePoint(Base64.decode((String) jsonData.get("e2")));
        this.v2 = params.getCurve().decodePoint(Base64.decode((String) jsonData.get("v2")));

        this.commitment = params.getCurve().decodePoint(Base64.decode((String) jsonData.get("commitment")));
        this.pok = params.getCurve().decodePoint(Base64.decode((String) jsonData.get("pok")));

        this.sig_key = new BigInteger(Base64.decode((String) jsonData.get("sig_key")));
        this.signature = Base64.decode((String) jsonData.get("signature"));
        if (jsonData.containsKey("metadata"))
            this.metadata = Base64.decode((String) jsonData.get("metadata"));
    }

    public String toJson() {
        Gson gson = new Gson();

        Map<String, String> jsonData = new TreeMap<>() {{
            put("e2", new String(Base64.encode(e2.getEncoded(true))));
            put("v2", new String(Base64.encode(v2.getEncoded(true))));
            put("commitment", new String(Base64.encode(commitment.getEncoded(true))));
            put("pok", new String(Base64.encode(pok.getEncoded(true))));
            put("sig_key", new String(Base64.encode(sig_key.toByteArray())));
            put("signature", new String(Base64.encode(signature)));
        }};
        if (metadata != null) {
            jsonData.put("metadata", new String(Base64.encode(metadata)));
        }
        return gson.toJson(jsonData, TreeMap.class);
    }

    public CorrectnessProof(ECPoint e2, ECPoint v2, ECPoint commitment, ECPoint pok, BigInteger sig_key, byte[] signature, byte[] metadata) {
        this.e2 = e2;
        this.v2 = v2;
        this.commitment = commitment;
        this.pok = pok;
        this.sig_key = sig_key;
        this.signature = signature;
        this.metadata = metadata;
    }

}
