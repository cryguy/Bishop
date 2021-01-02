package my.ditto.bishop;
import com.google.gson.Gson;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.TreeMap;


public class Main {
    public static void main(String[] args) throws GeneralSecurityException, IOException {
        ECParameterSpec parameterSpec = Helpers.getRandomPrivateKey().getParameters();

        // args - 0
        // capsule
        if (args.length != 3) {
            System.out.println("Usage");
            System.out.println("bishop.jar <Capsule> <Verification Keys> <kFrag>");
            System.out.println("All parameters must be in base64");
        }
        else {
            Capsule capsule = new Capsule(new String(org.bouncycastle.util.encoders.Base64.decode(args[0])), parameterSpec);

            // args - 1 = {"alice":"123","bobpub":"123","aliceverify":"123"}
            Gson gson = new Gson();
            TreeMap keys = gson.fromJson(new String(org.bouncycastle.util.encoders.Base64.decode(args[1])), TreeMap.class);

            ECPublicKey alicePub = Helpers.getPublicKey(parameterSpec.getCurve().decodePoint(org.bouncycastle.util.encoders.Base64.decode((String) keys.get("alice"))));
            ECPublicKey bobPub = Helpers.getPublicKey(parameterSpec.getCurve().decodePoint(org.bouncycastle.util.encoders.Base64.decode((String) keys.get("alice"))));
            EdDSAPublicKey verify = new EdDSAPublicKey(new X509EncodedKeySpec(Helpers.hexStringToByteArray((String) keys.get("verify"))));

            // arg 2 - kfrag
            kFrag frag = new kFrag(new String(org.bouncycastle.util.encoders.Base64.decode(args[2])), alicePub.getParameters());
            capsule.set_correctness_key(alicePub, bobPub, verify);
            System.out.println(Base64.getEncoder().encodeToString(cFrag.reencrypt(frag, capsule, true, null, true).toJson().getBytes()));
        }
    }
}
