package dev.krypt04mcg.crypto;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class XChaCha20Poly1305Test {
    private static byte[] hex(String text) { return HexFormat.of().parseHex(text); }
    // Appendix A.3.1: entire ciphertext AND Poly1305 tag, independently published.
    @Test void aeadPublishedVectorAndTamperRejection() throws Exception {
        byte[] key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = hex("404142434445464748494a4b4c4d4e4f5051525354555657");
        byte[] aad = hex("50515253c0c1c2c3c4c5c6c7");
        byte[] plain = hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        byte[] expected = hex("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49");
        assertArrayEquals(expected, XChaCha20Poly1305.encrypt(key, nonce, aad, plain));
        assertArrayEquals(plain, XChaCha20Poly1305.decrypt(key, nonce, aad, expected));
        expected[0] ^= 1;
        assertThrows(CryptoException.class, () -> XChaCha20Poly1305.decrypt(key, nonce, aad, expected));
        assertThrows(CryptoException.class, () -> XChaCha20Poly1305.encrypt(key, new byte[12], aad, plain));
    }
}
