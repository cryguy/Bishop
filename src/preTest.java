import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
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
    void enc_decrypt_reencrypt_secp256k1() throws GeneralSecurityException, IOException {
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey();
        ECPublicKey alicePublic = Helpers.getPublicKey(alicePrivate);

        Ed25519PrivateKeyParameters aliceSigning = Helpers_ed25519.getRandomPrivateKey();
        Ed25519PublicKeyParameters aliceVerifying = Helpers_ed25519.getPublicKey(aliceSigning);

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
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(2), capsule, true, null, true));
        // should be able to decrypt now.
        Assertions.assertEquals(Helpers.bytesToHex(plaintext), Helpers.bytesToHex(pre.decrypt(ciphertext, capsule, bobPrivate, true)));
    }


    @Test
    void enc_decrypt_r_secp256k1() throws GeneralSecurityException, IOException {
        BigInteger aliceBigInt = new BigInteger("9cd8dc6db8d04aae20ce22ff899a743db9e2144682a69311c709d5c1849b8731", 16);
        ECPrivateKey alicePrivate = Helpers.getPrivateKey(aliceBigInt, Helpers.getRandomPrivateKey().getParameters()); // lazy...
        assert alicePrivate != null;
        SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(Helpers.getPublicKey(alicePrivate), "abc".getBytes());

        byte[] data = pre.decrypt(encrypt.getKey(), encrypt.getValue(), alicePrivate, true);
        assertEquals(Helpers.bytesToHex("abc".getBytes()), Helpers.bytesToHex(data));
    }


}