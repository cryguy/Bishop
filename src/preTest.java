import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class preTest {

    @org.junit.jupiter.api.Test
    void generate_kfrag() {
        fail();
    }

    @Test
    void _encapsulate() throws GeneralSecurityException {
        // following is proof that encapsulate works..., we cant unit test the actual method because we generate the bignumbers on the fly
        // TODO: will need to break the function down more...
        BigInteger aliceBigInt = new BigInteger("9cd8dc6db8d04aae20ce22ff899a743db9e2144682a69311c709d5c1849b8731", 16);
        ECPrivateKey alicePrivate = Helpers.getPrivateKey(aliceBigInt, Helpers.getRandomPrivateKey().getParameters()); // lazy...

        assert alicePrivate != null;
        ECParameterSpec params = alicePrivate.getParameters();
        ECPoint g = params.getG();
        BigInteger r = new BigInteger("4ba3751977ea826c4363da7b681c038eccfd4444bfa0e9b243e64782ecfb9cb6", 16);
        ECPoint pub_r = g.multiply(r);
        System.out.println("pub_r " + Helpers.bytesToHex(pub_r.getEncoded(true)));
        BigInteger u = new BigInteger("8ee27ccb8b4706b8377de832b49fbc0d48f8d793cefb117f0706e574f5614033", 16);
        ECPoint pub_u = g.multiply(u);
        System.out.println("pub_u " + Helpers.bytesToHex(pub_u.getEncoded(true)));
        BigInteger h = RandomOracle.hash2curve(new byte[][]{pub_r.getEncoded(true), pub_u.getEncoded(true)}, params);
        //5e16d87ac62b5b3b4fa528976a787002e2345d58b91cb5a029c3bdeec70e6ce0

        BigInteger s = u.add(r.multiply(h).mod(params.getCurve().getOrder())).mod(params.getCurve().getOrder());
        //008bcab77c6ec079d8e85d4e263633d79287d997bdc2238596920e0e39f3ad76
        System.out.println("s " + Helpers.bytesToHex(s.toByteArray()));

        ECPoint shared = Helpers.getPublicKey(alicePrivate).getQ().multiply(r.add(u).mod(params.getCurve().getOrder()));

        byte[] key = RandomOracle.kdf(shared.getEncoded(true), 32, "abc".getBytes(), null);
        assertEquals("648718e5e367af5b1e8d9111e6172f21f05cb6ef2209709bd70addbdf5b4e716".toUpperCase(), Helpers.bytesToHex(key));

    }
}