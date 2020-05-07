import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

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
        BigInteger blk2b = RandomOracle.hash2curve(new byte[][]{"HELLO WORLD".getBytes()}, Helpers.getRandomPrivateKey().getParameters());
        assertEquals("0839CC346AA7C896379F51E44575375AD4A1B7EEEDC92C61BD85BFE116533259".toUpperCase(), Helpers.bytesToHex(blk2b.toByteArray()));
    }

    @Test
    void unsafeHash2Point() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        BigInteger aliceBigInt = new BigInteger("43941d9fb0fbbae48838afc7fc2ba23c22bdde8bc18b3d745c7c90dfd34d3aa1", 16);
        ECPrivateKey alicePrivate = Helpers.getPrivateKey(aliceBigInt, Helpers.getRandomPrivateKey().getParameters());
        assert alicePrivate != null;
        String result = Helpers.bytesToHex(RandomOracle.unsafeHash2Point(alicePrivate.getParameters().getG().getEncoded(true), "NuCypher/UmbralParameters/u".getBytes(), alicePrivate.getParameters()).getEncoded(true));
        assertEquals("027769A36D924905BDE272D32FE1C9663DF7671DCF689CE9FF31FC03D1A562A73C".toUpperCase(), result);
    }

    @Test
    void kdf() {
        // kdf of 02e22f7c2de1aa561353077a7c262bce46e84f1bf3ff41f8e33382c70a809b68bb with salt abc = 5f519ff05f4a80bd94965d4a29468deabf89831b651b734ccd22ee807d74c7b4
        assertEquals("5f519ff05f4a80bd94965d4a29468deabf89831b651b734ccd22ee807d74c7b4".toUpperCase(), Helpers.bytesToHex(RandomOracle.kdf(Helpers.hexStringToByteArray("02e22f7c2de1aa561353077a7c262bce46e84f1bf3ff41f8e33382c70a809b68bb"), 32, "abc".getBytes(), null)));
    }
}