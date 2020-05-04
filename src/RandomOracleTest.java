import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RandomOracleTest {

    @Test
    void getStringHash() throws NoSuchAlgorithmException {
        assertEquals("4c591cee9247687d".toUpperCase(), Helpers.bytesToHex(RandomOracle.getStringHash("NON_INTERACTIVE")));
    }

    @Test
    void chacha20_poly_enc() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        assertEquals("b0403e1bc059b5aa339a27d7f8fd6f1eb939877504aaa93c7722768d85c8f1".toUpperCase(), Helpers.bytesToHex(RandomOracle.chacha20_poly1305_enc(Helpers.hexStringToByteArray("b0403e1bc059b5aa339a27d7"), "abc".getBytes(), Helpers.hexStringToByteArray("e048c7cf69348da318fe21a3b307dab48716254ac0eb1c2c5e747b9fd60ec53c"), "shy".getBytes())));
    }

    @Test
    void chacha20_poly_dec() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        assertEquals(Helpers.bytesToHex("abc".getBytes()), Helpers.bytesToHex(RandomOracle.chacha20_poly1305_dec(Helpers.hexStringToByteArray("b0403e1bc059b5aa339a27d7f8fd6f1eb939877504aaa93c7722768d85c8f1"), Helpers.hexStringToByteArray("e048c7cf69348da318fe21a3b307dab48716254ac0eb1c2c5e747b9fd60ec53c"), "shy".getBytes())));
    }

    @Test
    void hash2curve() throws GeneralSecurityException {
        BigInteger aliceBigInt = new BigInteger("43941d9fb0fbbae48838afc7fc2ba23c22bdde8bc18b3d745c7c90dfd34d3aa1", 16);
        ECPrivateKey alicePrivate = Helpers.getPrivateKey(aliceBigInt, Helpers.getRandomPrivateKey().getParameters()); // lazy...
        assert alicePrivate != null;
        ECPoint precursor = alicePrivate.getParameters().getCurve().decodePoint(Helpers.hexStringToByteArray("020b5131dd2ede443030778694ecb9b3c7d787ba82618a982e493097a537dacc26"));
        ECPoint bob_key = alicePrivate.getParameters().getCurve().decodePoint(Helpers.hexStringToByteArray("034c4467526b0f16dbacd7571ca07ace7ab0ed51f7e39dc94a903521193cc5c41f"));
        ECPoint dh_point = alicePrivate.getParameters().getCurve().decodePoint(Helpers.hexStringToByteArray("03659391192b9d61f74adeebf34dcc8982af15a5f296a676740cc8f49dbe1fe4e7"));
        byte[][] input_d = {precursor.getEncoded(true), bob_key.getEncoded(true), dh_point.getEncoded(true), RandomOracle.getStringHash("NON_INTERACTIVE")};
        BigInteger blk2b = RandomOracle.hash2curve(input_d, alicePrivate.getParameters());
        assertEquals(new BigInteger("599c5d6cee4a673f916ebb85f58e725a1eaac1e7fc1f1c8b37837a73cee2915d",16),blk2b);
    }

    @Test
    void unsafeHash2Point() throws IOException {
        BigInteger aliceBigInt = new BigInteger("43941d9fb0fbbae48838afc7fc2ba23c22bdde8bc18b3d745c7c90dfd34d3aa1", 16);
        ECPrivateKey alicePrivate = Helpers.getPrivateKey(aliceBigInt, Helpers.getRandomPrivateKey().getParameters());
        assert alicePrivate != null;
        String result = Helpers.bytesToHex(RandomOracle.unsafeHash2Point(alicePrivate.getParameters().getG().getEncoded(true), "NuCypher/UmbralParameters/u".getBytes(), alicePrivate.getParameters()).getEncoded(true));
        assertEquals("0203c98795773ff1c241fc0b1cced85e80f8366581dda5c9452175ebd41385fa1f".toUpperCase(), result);
    }

    @Test
    void kdf() {
        // kdf of 02e22f7c2de1aa561353077a7c262bce46e84f1bf3ff41f8e33382c70a809b68bb with salt abc = 5f519ff05f4a80bd94965d4a29468deabf89831b651b734ccd22ee807d74c7b4
        assertEquals("5f519ff05f4a80bd94965d4a29468deabf89831b651b734ccd22ee807d74c7b4".toUpperCase(),Helpers.bytesToHex(RandomOracle.kdf(Helpers.hexStringToByteArray("02e22f7c2de1aa561353077a7c262bce46e84f1bf3ff41f8e33382c70a809b68bb"),32,"abc".getBytes(), null)));
    }
}