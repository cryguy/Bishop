package my.ditto.bishop;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class preTest {

    @Test
    void test_Capsule_serialization() throws GeneralSecurityException, IOException {
        // given compressed bytes, able to retrieve original ECPoint, sanity check...

        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey();
        ECPublicKey alicePublic = Helpers.getPublicKey(alicePrivate);

        byte[] plaintext = "Hello World!".getBytes();

        SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(alicePublic, plaintext, null);

        Capsule capsule = encrypt.getValue();
        System.out.println(capsule.toJson());
        assertEquals(capsule, new Capsule(capsule.toJson(), alicePrivate.getParameters()));

    }

    @Test
    void test_self_decrypt() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey(); // lazy...
        SecureRandom random = new SecureRandom();
        byte[] file = new byte[1000000 * 15]; //15mb
        random.nextBytes(file);
        long startTime = System.nanoTime();
        SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(Helpers.getPublicKey(alicePrivate), file, "file1".getBytes());
        long endTime = System.nanoTime();
        long timetaken_enc = (endTime - startTime) / 1000000;
        System.out.println("Time for enc : " + timetaken_enc + " ms");
        startTime = System.nanoTime();
        byte[] cleardec = pre.decrypt(encrypt.getKey(), encrypt.getValue(), alicePrivate, true);
        endTime = System.nanoTime();
        long timetaken_dec = (endTime - startTime) / 1000000;
        System.out.println("Time for dec : " + timetaken_dec + " ms");
        assertEquals(Arrays.toString(file), Arrays.toString(cleardec));
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

        net.i2p.crypto.eddsa.KeyPairGenerator edDsaKpg = new net.i2p.crypto.eddsa.KeyPairGenerator();
        KeyPair keyPair = edDsaKpg.generateKeyPair();
        EdDSAPrivateKey aliceSigning = (EdDSAPrivateKey) keyPair.getPrivate();
        EdDSAPublicKey aliceVerifying = (EdDSAPublicKey) keyPair.getPublic();

        ECPrivateKey bobPrivate = Helpers.getRandomPrivateKey();
        ECPublicKey bobPublic = Helpers.getPublicKey(bobPrivate);

        //byte[] plaintext = "Hello World!".getBytes();

        SecureRandom random = new SecureRandom();
        byte[] file = new byte[1000000 * 15]; //15mb
        random.nextBytes(file);

        SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(alicePublic, file, null);

        byte[] ciphertext = encrypt.getKey();
        Capsule capsule = encrypt.getValue();
        {
            // try decrypt with alice's own key
            assertEquals(Helpers.bytesToHex(file), Helpers.bytesToHex(pre.decrypt(ciphertext, capsule, alicePrivate, true)));
        }
        {
            // try decrypt with bobs key without reencryption
            Assertions.assertThrows(GeneralSecurityException.class, () -> pre.decrypt(ciphertext, capsule, bobPrivate, true));
        }

        ArrayList<kFrag> kfrags = pre.generate_kFrag(alicePrivate, aliceSigning, bobPublic, 5, 10, null); // somehow works if N=1
        capsule.set_correctness_key(alicePublic, bobPublic, aliceVerifying);

        var test = pre.reencrypt(kfrags.get(0), capsule, true, null, true);
        capsule.attach_cfrag(test);
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
        // should be able to decrypt now.
        Assertions.assertEquals(Helpers.bytesToHex(file), Helpers.bytesToHex(pre.decrypt(ciphertext, capsule, bobPrivate, true)));
    }

    @Test
    void encrypt_decrypt() throws IOException, GeneralSecurityException {
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey bobPrivate = Helpers.getRandomPrivateKey();
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey(); // lazy...

        ECPoint shared = Helpers.getPublicKey(bobPrivate).getQ().multiply(alicePrivate.getD());

        var key = RandomOracle.kdf(shared.getEncoded(true), 32, null, null);

        var cipher = RandomOracle.chacha20_poly1305_enc("randomrandom".getBytes(), alicePrivate.getD().toByteArray(), key, null);
        System.out.println(cipher.length);

        var cipherhex = Helpers.bytesToHex(cipher);
        System.out.println(cipherhex + " " + cipherhex.length());
        var cleardec = RandomOracle.chacha20_poly1305_dec(cipher, key, null);
        assertEquals(Arrays.toString(alicePrivate.getD().toByteArray()), Arrays.toString(cleardec));

    }


    private byte[] xorWithKey(byte[] a, byte[] key) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ key[i % key.length]);
        }
        return out;
    }

    @Test
    void encrypt_decrypt_saaif() throws GeneralSecurityException {
        // this test can fail if the generated key is unsuitable, this happens in about 10% of the cases...
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey bobPrivate = Helpers.getRandomPrivateKey();
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey(); // lazy...

        ECPoint shared = Helpers.getPublicKey(bobPrivate).getQ().multiply(alicePrivate.getD());

        var key = RandomOracle.kdf(shared.getEncoded(true), 32, null, null);

        var ciphertext = xorWithKey(alicePrivate.getD().toByteArray(), key);

        var decrypted = xorWithKey(ciphertext, key);
        BigInteger alice = new BigInteger(decrypted);
        assertEquals(alice, alicePrivate.getD());
        assertEquals(Helpers.bytesToHex(alicePrivate.getD().toByteArray()), Helpers.bytesToHex(decrypted));
        int[] mnemonic = Helpers.to_mnemonic(ciphertext);
        byte[] aftermne = Helpers.from_mneumonic(mnemonic);
        assertEquals(Helpers.bytesToHex(ciphertext), Helpers.bytesToHex(aftermne));
    }

    @Test
    void test_proxy_decrypt_with_meta() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey();
        ECPublicKey alicePublic = Helpers.getPublicKey(alicePrivate);

        net.i2p.crypto.eddsa.KeyPairGenerator edDsaKpg = new net.i2p.crypto.eddsa.KeyPairGenerator();
        KeyPair keyPair = edDsaKpg.generateKeyPair();

        EdDSAPrivateKey aliceSigning = (EdDSAPrivateKey) keyPair.getPrivate();
        EdDSAPublicKey aliceVerifying = (EdDSAPublicKey) keyPair.getPublic();

        ECPrivateKey bobPrivate = Helpers.getRandomPrivateKey();
        ECPublicKey bobPublic = Helpers.getPublicKey(bobPrivate);

        //byte[] plaintext = "Hello World!".getBytes();
        SecureRandom random = new SecureRandom();
        byte[] plaintext = new byte[1000000 * 15];
        random.nextBytes(plaintext);

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

        ArrayList<kFrag> kfrags = pre.generate_kFrag(alicePrivate, aliceSigning, bobPublic, 5, 10, "with metadata!".getBytes());
        capsule.set_correctness_key(alicePublic, bobPublic, aliceVerifying);

        ArrayList<cFrag> cfrags = new ArrayList<>();
        for (my.ditto.bishop.kFrag kFrag : kfrags) {
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
        // all is good
        Assertions.assertEquals(Helpers.bytesToHex(plaintext), Helpers.bytesToHex(pre.decrypt(ciphertext, capsule, bobPrivate, true)));

        capsule._attached_cfag.clear();

        {
            // try doing some bs... as an attacker
            ArrayList<kFrag> kfrags_diffmeta = pre.generate_kFrag(alicePrivate, aliceSigning, bobPublic, 1, 2, "WRONG".getBytes());
            //capsule.attach_cfrag();
            Capsule capsule1 = new Capsule(capsule.params, capsule.point_e, capsule.point_v, capsule.signaure, "WRONG".getBytes(), capsule.hash);
            capsule1.correctness_key = capsule.correctness_key;

            assertThrows(GeneralSecurityException.class, () -> capsule1._attached_cfag.add(pre.reencrypt(kfrags_diffmeta.get(0), capsule1, true, null, true)));
            assertThrows(GeneralSecurityException.class, () -> pre.decrypt(ciphertext, capsule1, bobPrivate, true));
            assertThrows(GeneralSecurityException.class, () -> pre.decapsulateReencrypted(bobPrivate, capsule1, 32, capsule.metadata));
        }

    }

    @Test
    void test_proxy_decrypt_adversary() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey();
        ECPublicKey alicePublic = Helpers.getPublicKey(alicePrivate);
        net.i2p.crypto.eddsa.KeyPairGenerator edDsaKpg = new net.i2p.crypto.eddsa.KeyPairGenerator();
        KeyPair keyPair = edDsaKpg.generateKeyPair();
        EdDSAPrivateKey aliceSigning = (EdDSAPrivateKey) keyPair.getPrivate();
        EdDSAPublicKey aliceVerifying = (EdDSAPublicKey) keyPair.getPublic();

        ECPrivateKey bobPrivate = Helpers.getRandomPrivateKey();
        ECPublicKey bobPublic = Helpers.getPublicKey(bobPrivate);


        ECPrivateKey attackerPrivate = Helpers.getRandomPrivateKey();
        ECPublicKey attackerPublic = Helpers.getPublicKey(bobPrivate);
        //byte[] plaintext = "Hello World!".getBytes();
        SecureRandom random = new SecureRandom();
        byte[] plaintext = new byte[1000000 * 15];
        random.nextBytes(plaintext);

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

        ArrayList<kFrag> kfrags = pre.generate_kFrag(alicePrivate, aliceSigning, bobPublic, 5, 10, "with metadata!".getBytes());
        capsule.set_correctness_key(alicePublic, bobPublic, aliceVerifying);

        ArrayList<cFrag> cfrags = new ArrayList<>();
        for (my.ditto.bishop.kFrag kFrag : kfrags) {
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

        Assertions.assertEquals(Helpers.bytesToHex(plaintext), Helpers.bytesToHex(pre.decrypt(ciphertext, capsule, alicePrivate, true)));
        // all is good for bob
        Assertions.assertEquals(Helpers.bytesToHex(plaintext), Helpers.bytesToHex(pre.decrypt(ciphertext, capsule, bobPrivate, true)));
        // should fail for attacker
        Assertions.assertThrows(GeneralSecurityException.class, () -> pre.decrypt(ciphertext, capsule, attackerPrivate, false));

    }
}