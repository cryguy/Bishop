package my.ditto.bishop;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FragmentsSerializationTest {

    @Test
    void serialization() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey();
        ECPublicKey alicePublic = Helpers.getPublicKey(alicePrivate);

        net.i2p.crypto.eddsa.KeyPairGenerator edDsaKpg = new net.i2p.crypto.eddsa.KeyPairGenerator();
        KeyPair keyPair = edDsaKpg.generateKeyPair();
        EdDSAPrivateKey aliceSigning = (EdDSAPrivateKey) keyPair.getPrivate();
        EdDSAPublicKey aliceVerifying = (EdDSAPublicKey) keyPair.getPublic();

        System.out.println(Helpers.bytesToHex(aliceVerifying.getEncoded()));
        X509EncodedKeySpec encoded = new X509EncodedKeySpec(Helpers.hexStringToByteArray(Helpers.bytesToHex(aliceVerifying.getEncoded())));

        EdDSAPublicKey keyIn = new EdDSAPublicKey(encoded);

        // Encode
        EdDSAPublicKeySpec decoded = new EdDSAPublicKeySpec(
                keyIn.getA(),
                keyIn.getParams());
        EdDSAPublicKey keyOut = new EdDSAPublicKey(decoded);

        // Check
        assertEquals(Helpers.bytesToHex(keyOut.getEncoded()), Helpers.bytesToHex(aliceVerifying.getEncoded()));

        ECPrivateKey bobPrivate = Helpers.getRandomPrivateKey();
        ECPublicKey bobPublic = Helpers.getPublicKey(bobPrivate);

        byte[] plaintext = "Hello World!".getBytes();
        AbstractMap.SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(alicePublic, plaintext, null);

        Capsule capsule = encrypt.getValue();

        ArrayList<kFrag> kfrags = pre.generate_kFrag(alicePrivate, aliceSigning, bobPublic, 2, 3, null);

        System.out.println(kfrags.get(0).toJson());

        kFrag testfrag = new kFrag(kfrags.get(0).toJson(), alicePrivate.getParameters());
        capsule.set_correctness_key(alicePublic, bobPublic, aliceVerifying);

        assertTrue(testfrag.verify_for_capsule(capsule));
        var test = pre.reencrypt(testfrag, capsule, true, null, true);
        System.out.println(test.toJson());

        var cFragAfterTransmit = new cFrag(test.toJson(), alicePrivate.getParameters());

        assertTrue(cFragAfterTransmit.verify_correctness(capsule));
    }
}