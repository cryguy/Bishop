package my.ditto.bishop;

import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class CorrectnessProof {
    // TODO: implement deserialization
    ECPoint e2;
    ECPoint v2;
    ECPoint commitment;
    ECPoint pok;
    BigInteger sig_key;
    byte[] signature;
    byte[] metadata;

    public CorrectnessProof(ECPoint e2, ECPoint v2, ECPoint commitment, ECPoint pok, BigInteger sig_key, byte[] signature) {
        this(e2, v2, commitment, pok, sig_key, signature, null);
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

    public byte[] to_bytes() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(e2.getEncoded(true));
        outputStream.write(v2.getEncoded(true));
        outputStream.write(commitment.getEncoded(true));
        outputStream.write(pok.getEncoded(true));
        outputStream.write(sig_key.toByteArray());
        outputStream.write(signature);
        if (metadata != null)
            outputStream.write(metadata);
        return outputStream.toByteArray();
    }
}
