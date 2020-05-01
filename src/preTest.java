import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class preTest {

    @org.junit.jupiter.api.Test
    void getStringHash() throws NoSuchAlgorithmException {
        assertEquals("4c591cee9247687d".toUpperCase(),Helpers.bytesToHex(pre.getStringHash("NON_INTERACTIVE")));
    }
    @org.junit.jupiter.api.Test
    void hash2curve() throws GeneralSecurityException {
        BigInteger aliceBigInt = new BigInteger("43941d9fb0fbbae48838afc7fc2ba23c22bdde8bc18b3d745c7c90dfd34d3aa1", 16);
        ECPrivateKey alicePrivate = pre.getPrivateKey(aliceBigInt,pre.getRandomPrivateKey().getParameters()); // lazy...
        ECPoint precursor = alicePrivate.getParameters().getCurve().decodePoint(Helpers.hexStringToByteArray("020b5131dd2ede443030778694ecb9b3c7d787ba82618a982e493097a537dacc26"));
        ECPoint bob_key = alicePrivate.getParameters().getCurve().decodePoint(Helpers.hexStringToByteArray("034c4467526b0f16dbacd7571ca07ace7ab0ed51f7e39dc94a903521193cc5c41f"));
        ECPoint dh_point = alicePrivate.getParameters().getCurve().decodePoint(Helpers.hexStringToByteArray("03659391192b9d61f74adeebf34dcc8982af15a5f296a676740cc8f49dbe1fe4e7"));

        byte[][] input_d = {precursor.getEncoded(true),bob_key.getEncoded(true), dh_point.getEncoded(true),pre.getStringHash("NON_INTERACTIVE")};
        BigInteger blk2b = pre.hash2curve(input_d, alicePrivate.getParameters());
        assertEquals(new BigInteger("599c5d6cee4a673f916ebb85f58e725a1eaac1e7fc1f1c8b37837a73cee2915d",16),blk2b);
    }
    @org.junit.jupiter.api.Test
    void generate_kfrag() {
    }
}