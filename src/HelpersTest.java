import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HelpersTest {

    @Test
    void lambda_coeff_secp256k1() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        BigInteger id_i = new BigInteger("b5aa4fdd5f4476d9cde31e01aa11e0f8f5bde05f5100f9db8e2b0baeb91692d7", 16);
        BigInteger[] ids = new BigInteger[]{id_i, new BigInteger("f575f5c7c78b62b11d4463821056d7af0e94f83bf4c1202fc6410a7a88b8f861", 16), new BigInteger("b9136323dd6fe6244eda7350337b13dc9030dd6541c7e5f2304688a8bd3550e1", 16), new BigInteger("f99c31b318c553cd6d20b88245061fc56207ca1793ab8af0cc23f1d5c946b1c4", 16), new BigInteger("bddd6885ebfb9699294655f1c225bbd6f6b0e3ac54063b292222a4ece1dec0a5", 16), new BigInteger("e0f27f1d972f20caada310f9e903a0b19967b6f939ac9a3e9c75715ada242e9c", 16), new BigInteger("d20ed2a11713c129d7e90bf37fa2d2e5b9895f3b1f08865b8e6dcc33cfd8329d", 16), new BigInteger("e9aca197ee08249cc7d3a6d0b11df69f5f10e451b849e2311eab31af87d815b7", 16), new BigInteger("56b56d8068aa4e3e09d9761812492b3dbba811735291a224b913332671a510d9", 16), new BigInteger("d93f75df1b1b2346cb60ad140619cd127bcfe29a0aa133d5f7304c759c144e6b", 16)};
        assertEquals("02b7cfd3d4c6d5883dc6da588bb2a34a6402663d86639ae8381f6f0ca0627462".toUpperCase(), Helpers.bytesToHex(Helpers.lambda_coeff(id_i, ids, Helpers.getRandomPrivateKey().getParameters()).toByteArray()));
    }

}