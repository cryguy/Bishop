package my.ditto.bishop;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.junit.jupiter.api.Test;
import org.spongycastle.jce.interfaces.ECPrivateKey;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.util.AbstractMap;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertTrue;

class FragmentsSerializationTest {

    @Test
    void serialization() throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        ECPrivateKey alicePrivate = Helpers.getRandomPrivateKey();
        ECPublicKey alicePublic = Helpers.getPublicKey(alicePrivate);

        ECPrivateKey bobPrivate = Helpers.getRandomPrivateKey();
        ECPublicKey bobPublic = Helpers.getPublicKey(bobPrivate);

        net.i2p.crypto.eddsa.KeyPairGenerator edDsaKpg = new net.i2p.crypto.eddsa.KeyPairGenerator();
        KeyPair keyPair = edDsaKpg.generateKeyPair();
        EdDSAPrivateKey aliceSigning = (EdDSAPrivateKey) keyPair.getPrivate();
        EdDSAPublicKey aliceVerifying = (EdDSAPublicKey) keyPair.getPublic();

//        //System.out.println(Helpers.bytesToHex(aliceVerifying.getEncoded()));
//        X509EncodedKeySpec encoded = new X509EncodedKeySpec(Helpers.hexStringToByteArray(Helpers.bytesToHex(aliceVerifying.getEncoded())));
//
//        EdDSAPublicKey keyIn = new EdDSAPublicKey(encoded);
//
//        // Encode
//        EdDSAPublicKeySpec decoded = new EdDSAPublicKeySpec(
//                keyIn.getA(),
//                keyIn.getParams());
//        EdDSAPublicKey keyOut = new EdDSAPublicKey(decoded);
//
//        // Check
//        assertEquals(Helpers.bytesToHex(keyOut.getEncoded()), Helpers.bytesToHex(aliceVerifying.getEncoded()));



        byte[] plaintext = "Hello World!".getBytes();
        AbstractMap.SimpleEntry<byte[], Capsule> encrypt = pre.encrypt(alicePublic, plaintext, null);

        Capsule capsule = encrypt.getValue();
        //System.out.println("Capsule : " + capsule.toJson());
        ArrayList<kFrag> kfrags = kFrag.generate_kFrag(alicePrivate, aliceSigning, bobPublic, 1, 1, null);

//        System.out.println("alice Private : " + alicePrivate.getD().toString(16));
//        System.out.println("alice Signing : " + Helpers.bytesToHex(aliceSigning.getSeed()));
//        System.out.println("bob Public    : " + Helpers.bytesToHex(bobPublic.getQ().getEncoded(true)));
//        System.out.println("bob Private   : " + bobPrivate.getD().toString(16));


//        System.out.println(kfrags.get(0).toJson());
        kFrag testfrag = new kFrag(kfrags.get(0).toJson(), alicePrivate.getParameters());
        capsule.set_correctness_key(alicePublic, bobPublic, aliceVerifying);

        assertTrue(testfrag.verify_for_capsule(capsule));
        var test = cFrag.reencrypt(testfrag, capsule, true, null, true);
//        System.out.println(test.proof.toJson());
//
////        System.out.println(test.specialPrint());
//        System.out.println("CIPHER " + Helpers.bytesToHex(encrypt.getKey()));
        var cFragAfterTransmit = new cFrag(test.toJson(), alicePrivate.getParameters());
        capsule.attach_cfrag(cFragAfterTransmit);
        pre.decrypt(encrypt.getKey(), capsule, bobPrivate,true);
        assertTrue(cFragAfterTransmit.verify_correctness(capsule));
    }
}