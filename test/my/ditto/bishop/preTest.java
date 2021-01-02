package my.ditto.bishop;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.spongycastle.jce.interfaces.ECPrivateKey;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

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
        assertEquals(capsule, new Capsule(capsule.toJson(), alicePrivate.getParameters()));

    }

    @Test
    void test_self_decrypt() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey(); // lazy...
        SecureRandom random = new SecureRandom();
        byte[] file = new byte[1]; //15mb
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

        // metadata should be private so... need to implement diff test
        assertThrows(GeneralSecurityException.class, () -> pre.decrypt(encrypt.getKey(), pre.encrypt(Helpers.getPublicKey(alicePrivate), file, null).getValue(), alicePrivate, true));
        assertThrows(GeneralSecurityException.class, () -> pre.decrypt(encrypt.getKey(), pre.encrypt(Helpers.getPublicKey(alicePrivate), file, "FILE1".getBytes()).getValue(), alicePrivate, true));
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

        ArrayList<kFrag> kfrags = kFrag.generate_kFrag(alicePrivate, aliceSigning, bobPublic, 5, 10, null); // somehow works if N=1
        capsule.set_correctness_key(alicePublic, bobPublic, aliceVerifying);

        var test = cFrag.reencrypt(kfrags.get(0), capsule, true, null, true);
        capsule.attach_cfrag(test);
        {
            // not enough cfrags
            Assertions.assertThrows(GeneralSecurityException.class, () -> pre.decrypt(ciphertext, capsule, bobPrivate, true));
        }

        {
            ECParameterSpec parameterSpec = Helpers.getRandomPrivateKey().getParameters();

            // args - 0
            // capsule
            Capsule capsulete = new Capsule(capsule.toJson(),parameterSpec);

            capsulete.set_correctness_key(alicePublic,bobPublic,aliceVerifying);
            kFrag frag = new kFrag(kfrags.get(0).toJson(), parameterSpec);

            assertTrue(cFrag.reencrypt(frag, capsulete, true, null, true).verify_correctness(capsule));
        }




        // enough cfrags
        capsule._attached_cfag.clear();
        capsule.attach_cfrag(cFrag.reencrypt(kfrags.get(0), capsule, true, null, true));
        capsule.attach_cfrag(cFrag.reencrypt(kfrags.get(1), capsule, true, null, true));
        capsule.attach_cfrag(cFrag.reencrypt(kfrags.get(2), capsule, true, null, true));
        capsule.attach_cfrag(cFrag.reencrypt(kfrags.get(3), capsule, true, null, true));
        capsule.attach_cfrag(cFrag.reencrypt(kfrags.get(4), capsule, true, null, true));
        // should be able to decrypt now.
        Assertions.assertEquals(Helpers.bytesToHex(file), Helpers.bytesToHex(pre.decrypt(ciphertext, capsule, bobPrivate, true)));
    }

    @Test
    void encrypt_decrypt() throws IOException, GeneralSecurityException {
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey bobPrivate = Helpers.getRandomPrivateKey();
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey(); // lazy...

        ECPoint shared = Helpers.getPublicKey(bobPrivate).getQ().multiply(alicePrivate.getD());

        byte[] key = RandomOracle.kdf(shared.getEncoded(true), 32, null, null);

        byte[] cipher = RandomOracle.chacha20_poly1305_enc("randomrandom".getBytes(), alicePrivate.getD().toByteArray(), key, null);
        System.out.println(cipher.length);

        String cipherhex = Helpers.bytesToHex(cipher);
        System.out.println(cipherhex + " " + cipherhex.length());
        byte[] cleardec = RandomOracle.chacha20_poly1305_dec(cipher, key, null);
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

        ArrayList<kFrag> kfrags = kFrag.generate_kFrag(alicePrivate, aliceSigning, bobPublic, 5, 10, "with metadata!".getBytes());
        capsule.set_correctness_key(alicePublic, bobPublic, aliceVerifying);

        ArrayList<cFrag> cfrags = new ArrayList<>();
        for (my.ditto.bishop.kFrag kFrag : kfrags) {
            cfrags.add(cFrag.reencrypt(kFrag, capsule, true, null, true));
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
            ArrayList<kFrag> kfrags_diffmeta = kFrag.generate_kFrag(alicePrivate, aliceSigning, bobPublic, 1, 2, "WRONG".getBytes());
            //capsule.attach_cfrag();
            Capsule capsule1 = new Capsule(capsule.params, capsule.point_e, capsule.point_v, capsule.signaure, "WRONG".getBytes(), capsule.hash);
            capsule1.correctness_key = capsule.correctness_key;

            assertThrows(GeneralSecurityException.class, () -> capsule1._attached_cfag.add(cFrag.reencrypt(kfrags_diffmeta.get(0), capsule1, true, null, true)));
            assertThrows(GeneralSecurityException.class, () -> pre.decrypt(ciphertext, capsule1, bobPrivate, true));
            //assertThrows(GeneralSecurityException.class, () -> pre.decapsulateReencrypted(bobPrivate, capsule1, 32, capsule.metadata));
        }

    }

    @Test
    void decrypt_from_js() throws GeneralSecurityException, IOException {
        final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey alicePrivate = Helpers.getPrivateKey(new BigInteger("a4c620c5a815c3bc0196098f23e59202113b49a19de9008bc6a7f3296b52283",16),Helpers.getRandomPrivateKey().getParameters());
        ECPrivateKey bobPrivate = Helpers.getPrivateKey(new BigInteger("daf0e008eba2a042895f1407cd088016075bef72233560f47f3e8ed807fc306",16),Helpers.getRandomPrivateKey().getParameters());
        EdDSAPrivateKey aliceED = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(Helpers.hexStringToByteArray("88AB52BA555F47CD5BE569F6C6AE0CE5DF9B98D07AB84E7403F6BC3037DDA577"), ed25519));
        EdDSAPublicKey aliceEDpub = new EdDSAPublicKey(new EdDSAPublicKeySpec(aliceED.getA(), aliceED.getParams()));
        Capsule capsule = new Capsule("{\"point_e\":\"Aicz3V3pG4+hMBJjmmjP/WQI7s78dBiX1E9z8DC3fz0o\",\"point_v\":\"A0zMHZmYo1JyDLSaEPqkELranuS8gu4UD+NiVa6TVpgb\",\"signature\":\"AyKmbGDVR/KpprOsInTCYVhUpW8e5LLdBPcV0t6yjVY=\",\"hash\":\"eggYGWf7LLyhg5S/Bo+TM0JQA9leMYr5bh2qGWyQ2ZM=\",\"metadata\":\"\"}", alicePrivate.getParameters());
        kFrag kfrag = new kFrag("{\"identifier\":\"BxzqXU5Zdv4FzHP9yMe//lekj8Re9vPzDvfv5lhUVBY=\",\"bn_key\":\"DcpaUpDlNZGG26HJNGgZe38giC72ws2gywXCoTe4Jv8=\",\"point_commitment\":\"Ax5H8w/erMW37oIQbrXQUZ7UwXkyQ+r6y/iyQIVC4afH\",\"point_precursor\":\"A03Z8jOJfLKNG1oEz1qQX68WHl3MpIHi+10vpMJGluyG\",\"signature_for_proxy\":\"dlAVAruPixxpWfTawR3DhjoYQqBnPYdpfPz5y0rjE7syQ8B65ULIihHoBFS1GtUEYkKewsg+2/hP91HwEACJDQ==\",\"signature_for_bob\":\"pNvH/FIj2K/z3y34VswSJbw705olxMDg7HBr4WiJXo3n3NEc1mj7oa/V4pFrEAQiVpKkt9DvO3komQg84gdbDQ==\",\"key_in_signature\":\"Aw==\"}", alicePrivate.getParameters());
        capsule.set_correctness_key(Helpers.getPublicKey(alicePrivate),Helpers.getPublicKey(bobPrivate),aliceEDpub);

        ArrayList<kFrag> kf = kFrag.generate_kFrag(alicePrivate, aliceED, Helpers.getPublicKey(bobPrivate), 1,1, null);

        var a=pre.encrypt(Helpers.getPublicKey(alicePrivate),"Hello World!".getBytes(),null);
        System.out.println(Helpers.bytesToHex(a.getKey()));
        System.out.println(a.getValue().toJson());
        Capsule capsule1 = a.getValue();

        capsule1.set_correctness_key(Helpers.getPublicKey(alicePrivate),Helpers.getPublicKey(bobPrivate),aliceEDpub);

        kf.forEach(o -> {
            try {
                capsule1.attach_cfrag(cFrag.reencrypt(o, capsule1, true, null, true));
            } catch (GeneralSecurityException | IOException e) {
                e.printStackTrace();
            }
        });
        //5CC2AA72C28112C3B261C3A02FC387C399C3AA6965C382C3A6C293C3855F551446456E530FC2A4C39FC38216C2A2C2AE
        //5CAA728112F261E02FC7D9EA6965C2E693C55F551446456E530FA4DFC216A2AE

        pre.decrypt(a.getKey(), capsule1, bobPrivate,true);
        //pre.decrypt(Helpers.hexStringToByteArray("325386D036CDED5BD63459F28842F6F6A0AFC386C57869119B5E8702AF4147916787657D6EDFD1C7"), capsule, bobPrivate, true);
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

        ArrayList<kFrag> kfrags = kFrag.generate_kFrag(alicePrivate, aliceSigning, bobPublic, 5, 10, "with metadata!".getBytes());
        capsule.set_correctness_key(alicePublic, bobPublic, aliceVerifying);

        ArrayList<cFrag> cfrags = new ArrayList<>();
        for (my.ditto.bishop.kFrag kFrag : kfrags) {
            cfrags.add(cFrag.reencrypt(kFrag, capsule, true, null, true));
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