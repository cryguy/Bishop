import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;

class preTest {

    @org.junit.jupiter.api.Test
    void enc_decrypt_reencrypt() throws GeneralSecurityException, IOException {
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey();
        ECPublicKey alicePublic = Helpers.getPublicKey(alicePrivate);

        ECPrivateKey aliceSigning = Helpers.getRandomPrivateKey();
        ECPublicKey aliceVerifying = Helpers.getPublicKey(aliceSigning);

        ECPrivateKey bobPrivate = Helpers.getRandomPrivateKey();
        ECPublicKey bobPublic = Helpers.getPublicKey(bobPrivate);

        byte[] plaintext = "Hello World!".getBytes();

        SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(alicePublic, plaintext);

        byte[] ciphertext = encrypt.getKey();
        Capsule capsule = encrypt.getValue();

        {
            // try decrypt with alice's own key
            assertEquals(Helpers.bytesToHex(plaintext), Helpers.bytesToHex(pre.decrypt(ciphertext, capsule, alicePrivate, true)));
        }
        {
            // try decrypt with bobs key without reencryption
            Assertions.assertThrows(GeneralSecurityException.class, () -> pre.decrypt(ciphertext, capsule, bobPrivate, true));
        }

        ArrayList<kFrag> kfrags = pre.generate_kfrag(alicePrivate, aliceSigning, bobPublic, 5, 10); // somehow works if N=1
        capsule.set_correctness_key(alicePublic, bobPublic, aliceVerifying);

        ArrayList<cFrag> cfrags = new ArrayList<>();

        capsule.attach_cfrag(pre.reencrypt(kfrags.get(0), capsule, true, null, true));
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(7), capsule, true, null, true));
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(9), capsule, true, null, true));
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(3), capsule, true, null, true));

        {
            // not enough cfrags
            Assertions.assertThrows(SecurityException.class, () -> pre.decrypt(ciphertext, capsule, bobPrivate, true));
        }
        // enough cfrags
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(4), capsule, true, null, true));
        // should be able to decrypt now.
        Assertions.assertEquals(Helpers.bytesToHex(plaintext), Helpers.bytesToHex(pre.decrypt(ciphertext, capsule, bobPrivate, true)));
    }

    @Test
    void enc_decrypt() throws GeneralSecurityException, IOException {
        BigInteger aliceBigInt = new BigInteger("9cd8dc6db8d04aae20ce22ff899a743db9e2144682a69311c709d5c1849b8731", 16);
        ECPrivateKey alicePrivate = Helpers.getPrivateKey(aliceBigInt, Helpers.getRandomPrivateKey().getParameters()); // lazy...
        assert alicePrivate != null;
        SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(Helpers.getPublicKey(alicePrivate), "abc".getBytes());

        byte[] data = pre.decrypt(encrypt.getKey(), encrypt.getValue(), alicePrivate, true);
        assertEquals(Helpers.bytesToHex("abc".getBytes()), Helpers.bytesToHex(data));
    }


    @Test
    void gen_kfrag() throws GeneralSecurityException, IOException {
        ECPrivateKey alicePrivate = Helpers.getPrivateKey(new BigInteger("2c2cc05bfe741f229897385fcadb8691e8860974074c82e9f3de010bf647f953", 16), Helpers.getRandomPrivateKey().getParameters());
        ECPublicKey alicePublic = Helpers.getPublicKey(alicePrivate);

        ECPrivateKey aliceSigning = Helpers.getPrivateKey(new BigInteger("4a71bdbd0ee01a79566633b1b38bb206d56e0323d549f7d1497028563a757064", 16), alicePrivate.getParameters());

        ECPrivateKey bobPrivate = Helpers.getPrivateKey(new BigInteger("2f2144d7ee5b9ab4445cab9c362b08781475f4ce14c960db9d7cd22dfa2dad17", 16), alicePrivate.getParameters());
        ECPublicKey bobPublic = Helpers.getPublicKey(bobPrivate);
        ECPrivateKey precursor_priv = Helpers.getPrivateKey(new BigInteger("9dad512813608ab187ea15076341c829604dde0e336437f3e58cf1a89a3d5d09", 16), alicePrivate.getParameters());
        ECPoint dh_point = bobPublic.getQ().multiply(precursor_priv.getD());
        ECPoint precursor = alicePrivate.getParameters().getG().multiply(precursor_priv.getD());

        ArrayList<BigInteger> coefficients = new ArrayList<>();
        coefficients.add(new BigInteger("10e8bd4e74a4d8e023925fbd16f3094be37bf2edd04821fef960feb6b08b467c", 16));
        coefficients.add(new BigInteger("54fab2a55971651f7043408b335c891e75de2f71dfcc045338cfbde576b4ef97", 16));

        byte[] kfrag_1 = Helpers.hexStringToByteArray("87be080a36689e866216471e38816765a0b89fb046755ab9b3895887374879d6");
        byte[] kfrag_2 = Helpers.hexStringToByteArray("5dac547c63c9cc5ab70839acb6db5946373afa2220678c41920afef414346200");
        byte[] kfrag_3 = Helpers.hexStringToByteArray("e14c9c5b8e2d99545835fb59c6cf8c087eb10120d844191f855e18fcc08ef84c");

        kFrag kfrag1 = pre.getkFrag(bobPublic, aliceSigning, true, true, alicePrivate.getParameters(), alicePublic, bobPublic.getQ(), precursor, dh_point, coefficients, kfrag_1);
        kFrag kfrag2 = pre.getkFrag(bobPublic, aliceSigning, true, true, alicePrivate.getParameters(), alicePublic, bobPublic.getQ(), precursor, dh_point, coefficients, kfrag_2);
        kFrag kfrag3 = pre.getkFrag(bobPublic, aliceSigning, true, true, alicePrivate.getParameters(), alicePublic, bobPublic.getQ(), precursor, dh_point, coefficients, kfrag_3);

        // cfrags ok
        assertEquals("2b3e1fae500a051f9ca3feb80e0e1f72eec4d2ca78b3537ab9266a1ef5b59922", kfrag1.bn_key.toString(16));
        assertEquals("796757e79929c8695d33f88564340f9fc1b3d72f7286765291802c94f7b2c009", kfrag2.bn_key.toString(16));
        assertEquals("eaa8d8bf118899b50a9002b3d9c67797bfaf2581d74627c577521a9623090b7", kfrag3.bn_key.toString(16));

    }

}