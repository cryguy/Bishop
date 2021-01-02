package my.ditto.bishop;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HelpersTest {

    @Test
    void lambda_coeff_curve25519() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        BigInteger id_i = new BigInteger("b5aa4fdd5f4476d9cde31e01aa11e0f8f5bde05f5100f9db8e2b0baeb91692d7", 16);
        BigInteger[] ids = new BigInteger[]{id_i, new BigInteger("f575f5c7c78b62b11d4463821056d7af0e94f83bf4c1202fc6410a7a88b8f861", 16), new BigInteger("b9136323dd6fe6244eda7350337b13dc9030dd6541c7e5f2304688a8bd3550e1", 16), new BigInteger("f99c31b318c553cd6d20b88245061fc56207ca1793ab8af0cc23f1d5c946b1c4", 16), new BigInteger("bddd6885ebfb9699294655f1c225bbd6f6b0e3ac54063b292222a4ece1dec0a5", 16), new BigInteger("e0f27f1d972f20caada310f9e903a0b19967b6f939ac9a3e9c75715ada242e9c", 16), new BigInteger("d20ed2a11713c129d7e90bf37fa2d2e5b9895f3b1f08865b8e6dcc33cfd8329d", 16), new BigInteger("e9aca197ee08249cc7d3a6d0b11df69f5f10e451b849e2311eab31af87d815b7", 16), new BigInteger("56b56d8068aa4e3e09d9761812492b3dbba811735291a224b913332671a510d9", 16), new BigInteger("d93f75df1b1b2346cb60ad140619cd127bcfe29a0aa133d5f7304c759c144e6b", 16)};
        assertEquals("0C2E68C630E4493477635815B78D3C241541F77D4289B9C8AB209ECE1250BBE8".toUpperCase(), Helpers.bytesToHex(Helpers.lambda_coeff(id_i, ids, Helpers.getRandomPrivateKey().getParameters()).toByteArray()));
    }
    @Test
    void bctest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
       // Security.addProvider(new BouncyCastleProvider());
        System.out.println(Helpers.getRandomPrivateKey().getParameters().getCurve().getOrder());
    }

    @Test
    void ECDH() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleProvider());
        var precursorPrivate = Helpers.getRandomPrivateKey();

        var receiving_pubkey = Helpers.getPublicKey(Helpers.getRandomPrivateKey());

        //System.out.println("Private : " + Helpers.bytesToHex(precursorPrivate.getD().toByteArray()));
        //System.out.println("Public  : " + Helpers.bytesToHex(receiving_pubkey.getQ().getEncoded(true)));

        var dh = Helpers.doECDH(precursorPrivate, receiving_pubkey);

        //System.out.println("DH : " + Helpers.bytesToHex(dh));
    }
    @Test
    void poly_eval() throws GeneralSecurityException {
        BigInteger blk2b = RandomOracle.hash2curve(new byte[][]{"HELLO WORLD".getBytes()}, Helpers.getRandomPrivateKey().getParameters());
        BigInteger a = new BigInteger("0AC88D67CA8D343FBCF9DA70C154F95BCE2F6A455530D4A184E8EC2BEF456500", 16);
        BigInteger b = new BigInteger("01299FD98A2B38E695F1A5DCD6869FE0D7C7A649C9236B33CB4C69077EBB5953", 16);
        BigInteger c = new BigInteger("0904CF805D479E9789E387C8A98EE79F0164DC813F50A2362E98644481B64589", 16);
        BigInteger[] arr = new BigInteger[]{a,b,c};
        assertEquals("0D4EE6A67F7171E0F55BB5D8BF8538D69F74FB3DEF1FE4AD72CAB95BA6CA25B8",Helpers.bytesToHex(Helpers.poly_eval(arr, blk2b, Helpers.getRandomPrivateKey().getParameters().getCurve().getOrder()).toByteArray()));

    }
}