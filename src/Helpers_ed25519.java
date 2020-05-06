import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;

public class Helpers_ed25519 {


    static Ed25519PrivateKeyParameters getPrivateKey(byte[] privatekey) {
        var privateKey = new Ed25519PrivateKeyParameters(privatekey, 0);
        return privateKey;
    }

    //keygen
    static Ed25519PrivateKeyParameters getRandomPrivateKey() {
        Security.addProvider(new BouncyCastleProvider());
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        SecureRandom secureRandom = new SecureRandom();
        gen.init(new Ed25519KeyGenerationParameters(secureRandom));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) kp.getPrivate();
        return privateKey;
    }

    static Ed25519PublicKeyParameters getPublicKey(Ed25519PrivateKeyParameters privateKey) throws GeneralSecurityException {
        return privateKey.generatePublicKey();
    }

}


