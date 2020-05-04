import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HelpersTest {

    @Test
    void lambda_coeff() {
        BigInteger id_i = new BigInteger("4f1132d0fd0cce6e17fa71af96830088d861eb43d56df1dab45b9514dd4e4791", 16);
        BigInteger[] ids = new BigInteger[]{new BigInteger("369affe763b4e53427c1eedadbfe55c1158742ba6a23919c4f85758be449d758", 16), new BigInteger("c20490edc2abe50156c4e6b3d0b52b9b011890845d8fdf68930e01c249c6ce6f", 16), new BigInteger("904295ae87e7aab4b48f2c70c534262596b972ba40a84d470c5c3dbd30f33e84", 16)};
        assertEquals("49deb0484a4d6d8b73b9073a4e9f362d3e2841514fa6b06e63dea08f25897185", Helpers.lambda_coeff(id_i, ids, Helpers.getRandomPrivateKey().getParameters()).toString(16));
    }
}