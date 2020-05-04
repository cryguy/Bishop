import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.AbstractMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class preTest {

    @org.junit.jupiter.api.Test
    void enc_decrypt_reencrypt() {
        fail();
    }


    @Test
        // encapsulate is tested here as well..
    void enc_decrypt() throws GeneralSecurityException, IOException {
        BigInteger aliceBigInt = new BigInteger("9cd8dc6db8d04aae20ce22ff899a743db9e2144682a69311c709d5c1849b8731", 16);
        ECPrivateKey alicePrivate = Helpers.getPrivateKey(aliceBigInt, Helpers.getRandomPrivateKey().getParameters()); // lazy...
        assert alicePrivate != null;
        AbstractMap.SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(Helpers.getPublicKey(alicePrivate), "abc".getBytes());

        byte[] data = pre.decrypt(encrypt.getKey(), encrypt.getValue(), alicePrivate, true);
        assertEquals(Helpers.bytesToHex("abc".getBytes()), Helpers.bytesToHex(data));
    }
}