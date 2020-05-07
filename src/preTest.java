import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class preTest {
    @Test
    void test_self_decrypt() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        BigInteger aliceBigInt = new BigInteger("9cd8dc6db8d04aae20ce22ff899a743db9e2144682a69311c709d5c1849b8731", 16);
        ECPrivateKey alicePrivate = Helpers.getPrivateKey(aliceBigInt, Helpers.getRandomPrivateKey().getParameters()); // lazy...
        assert alicePrivate != null;
        SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(Helpers.getPublicKey(alicePrivate), "abc".getBytes(), "file1".getBytes());
        assertEquals(Arrays.toString("abc".getBytes()), Arrays.toString(pre.decrypt(encrypt.getKey(), encrypt.getValue(), alicePrivate, true)));
        assertThrows(GeneralSecurityException.class, () -> {
            Capsule modified = encrypt.getValue();
            modified.metadata = null;
            pre.decrypt(encrypt.getKey(), modified, alicePrivate, true);
        });
        assertThrows(GeneralSecurityException.class, () -> {
            Capsule modified = encrypt.getValue();
            modified.metadata = "FILE1".getBytes();
            pre.decrypt(encrypt.getKey(), modified, alicePrivate, true);
        });
    }

    @Test
    void test_proxy_decrypt_without_meta() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey();
        ECPublicKey alicePublic = Helpers.getPublicKey(alicePrivate);
        Ed25519PrivateKeyParameters aliceSigning = Helpers_ed25519.getRandomPrivateKey();
        Ed25519PublicKeyParameters aliceVerifying = Helpers_ed25519.getPublicKey(aliceSigning);

        ECPrivateKey bobPrivate = Helpers.getRandomPrivateKey();
        ECPublicKey bobPublic = Helpers.getPublicKey(bobPrivate);

        byte[] plaintext = "Hello World!".getBytes();

        SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(alicePublic, plaintext, null);

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

        ArrayList<kFrag> kfrags = pre.generate_kfrag(alicePrivate, aliceSigning, bobPublic, 5, 10, null); // somehow works if N=1
        capsule.set_correctness_key(alicePublic, bobPublic, aliceVerifying);

        ArrayList<cFrag> cfrags = new ArrayList<>();

        capsule.attach_cfrag(pre.reencrypt(kfrags.get(0), capsule, true, null, true));
        {
            // not enough cfrags
            Assertions.assertThrows(GeneralSecurityException.class, () -> pre.decrypt(ciphertext, capsule, bobPrivate, true));
        }
        // enough cfrags
        capsule._attached_cfag.clear();
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(0), capsule, true, null, true));
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(1), capsule, true, null, true));
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(2), capsule, true, null, true));
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(3), capsule, true, null, true));
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(4), capsule, true, null, true));
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(5), capsule, true, null, true));
        capsule.attach_cfrag(pre.reencrypt(kfrags.get(6), capsule, true, null, true));
        // should be able to decrypt now.
        Assertions.assertEquals(Helpers.bytesToHex(plaintext), Helpers.bytesToHex(pre.decrypt(ciphertext, capsule, bobPrivate, true)));
    }

    @Test
    void test_proxy_decrypt_with_meta() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey();
        ECPublicKey alicePublic = Helpers.getPublicKey(alicePrivate);
        Ed25519PrivateKeyParameters aliceSigning = Helpers_ed25519.getRandomPrivateKey();
        Ed25519PublicKeyParameters aliceVerifying = Helpers_ed25519.getPublicKey(aliceSigning);

        ECPrivateKey bobPrivate = Helpers.getRandomPrivateKey();
        ECPublicKey bobPublic = Helpers.getPublicKey(bobPrivate);

        byte[] plaintext = "Hello World!".getBytes();

        SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(alicePublic, plaintext, "with metadata!".getBytes());

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

        ArrayList<kFrag> kfrags = pre.generate_kfrag(alicePrivate, aliceSigning, bobPublic, 5, 10, "with metadata!".getBytes());
        capsule.set_correctness_key(alicePublic, bobPublic, aliceVerifying);

        ArrayList<cFrag> cfrags = new ArrayList<>();
        for (kFrag kFrag : kfrags) {
            cfrags.add(pre.reencrypt(kFrag, capsule, true, null, true));
        }
        capsule.attach_cfrag(cfrags.get(0));
        {
            // not enough cfrags
            Assertions.assertThrows(GeneralSecurityException.class, () -> pre.decrypt(ciphertext, capsule, bobPrivate, true));
        }

        {
            Capsule capsule1 = new Capsule(capsule.params, capsule.point_e, capsule.point_v, capsule.signaure, "WRONGMETA".getBytes(), capsule.hash);
            // try decrypt with bobs key without reencryption
            Assertions.assertThrows(GeneralSecurityException.class, () -> pre.decrypt(ciphertext, capsule1, bobPrivate, true));
        }


        capsule._attached_cfag.clear();
        for (cFrag cFrag : cfrags) {
            capsule.attach_cfrag(cFrag);
        }

        Assertions.assertEquals(Helpers.bytesToHex(plaintext), Helpers.bytesToHex(pre.decrypt(ciphertext, capsule, bobPrivate, true)));

        capsule._attached_cfag.clear();
        ArrayList<kFrag> kfrags_diffmeta = pre.generate_kfrag(alicePrivate, aliceSigning, bobPublic, 5, 10, "WrongMeta".getBytes());
        Assertions.assertThrows(GeneralSecurityException.class, () -> capsule.attach_cfrag(pre.reencrypt(kfrags_diffmeta.get(0), capsule, true, null, true)));


    }
}