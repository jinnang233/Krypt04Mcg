package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.util.Base64Url;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.io.IOException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

final class SessionAuthenticationTest {
    private final CryptoService crypto = new CryptoService();
    private final PacketCodec codec = new PacketCodec();
    private final byte[] secret = new byte[32];
    private static final String ID = "AAAAAAAAAAAAAAAAAAAAAA";

    @Test
    void bothAeadsAuthenticateEverySessionHeaderFieldAndCiphertext() throws Exception {
        for (AeadAlgorithm aead : AeadAlgorithm.values()) {
            for (boolean compress : new boolean[] {false, true}) {
                EncryptedPacket p = crypto.encryptWithSession("bob", "alice", secret, ID, 7, "hello", compress, aead);
                EncryptedPacket decoded = codec.decode(codec.encode(p));
                assertEquals(ID, decoded.sessionId());
                assertEquals(7, decoded.sequence());
                assertFalse(decoded.signed());
                assertEquals(0, decoded.flags() & CryptoService.FLAG_SIGNED);
                assertEquals("NONE", decoded.algorithms().signature());
                assertEquals("hello", decrypt(decoded));
                // Pass the mutated context as expected context too: failure must come from AEAD,
                // rather than only from comparing the header with the stored session.
                for (int field = 0; field < 8; field++) {
                    byte[] ciphertext = p.ciphertext().clone();
                    byte[] nonce = p.nonce().clone();
                    byte[] messageId = p.messageId().clone();
                    if (field == 5) ciphertext[0] ^= 1;
                    if (field == 6) nonce[0] ^= 1;
                    if (field == 7) messageId[0] ^= 1;
                    EncryptedPacket changed = new EncryptedPacket(p.protocolVersion(), p.type(), p.flags(),
                            field == 0 ? "mallory" : p.sender(), field == 1 ? "carol" : p.receiver(),
                            p.timestampMillis() + (field == 4 ? 1 : 0), messageId, (short) 0, (short) 1,
                            p.algorithms(), nonce, p.kemCiphertext(), ciphertext, p.signature(),
                            field == 2 ? "AQAAAAAAAAAAAAAAAAAAAA" : p.sessionId(), p.sequence() + (field == 3 ? 1 : 0));
                    assertThrows(CryptoException.class, () -> decrypt(changed), "field " + field);
                }
                byte[] trailing = Arrays.copyOf(codec.encode(p), codec.encode(p).length + 4);
                assertThrows(IllegalArgumentException.class, () -> codec.decode(trailing));
                byte[] signed = codec.encode(p);
                signed[2] |= CryptoService.FLAG_SIGNED;
                assertThrows(IllegalArgumentException.class, () -> codec.decode(signed));
                for (byte version : new byte[] {1, 2, 3}) {
                    EncryptedPacket legacy = new EncryptedPacket(version, p.type(), p.flags(), p.sender(), p.receiver(),
                            p.timestampMillis(), p.messageId(), (short) 0, (short) 1, p.algorithms(), p.nonce(),
                            p.kemCiphertext(), p.ciphertext(), p.signature(), p.sessionId(), p.sequence());
                    assertThrows(CryptoException.class, () -> decrypt(legacy));
                }
            }
        }
    }

    @Test
    void replayWrongEpochAndOutOfOrderMessagesDoNotAdvanceState(@TempDir Path root) throws Exception {
        SessionService sessions = new SessionService(root);
        SessionRecord session = sessions.createLocalSession("alice", "kem:sig");
        byte[] key = Base64Url.decode(session.secret());
        EncryptedPacket p = crypto.encryptWithSession("bob", "alice", key, session.sessionId(), 0,
                "hello", false, AeadAlgorithm.AES_256_GCM);
        assertThrows(CryptoException.class, () -> crypto.decryptWithSession(p, "bob", "alice", key, ID, 0));
        assertThrows(CryptoException.class, () -> crypto.decryptWithSession(p, "bob", "alice", key, session.sessionId(), 1));
        assertEquals("hello", crypto.decryptWithSession(p, "bob", "alice", key, session.sessionId(), 0));
        sessions.recordReceivedMessage("alice", session.sessionId(), 0, 5);
        assertThrows(IOException.class, () -> sessions.recordReceivedMessage("alice", session.sessionId(), 0, 5));
        assertThrows(IOException.class, () -> sessions.recordReceivedMessage("alice", session.sessionId(), 2, 5));
        assertThrows(IOException.class, () -> sessions.recordReceivedMessage("alice", ID, 1, 5));
        assertEquals(1, sessions.find("alice").orElseThrow().nextReceiveSequence());
        assertEquals(1, sessions.find("alice").orElseThrow().messageCount());
    }

    @Test
    void exchangeStillRequiresValidPqSignature() throws Exception {
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "a", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.FALCON_512);
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "b", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.FALCON_512);
        PublicIdentity identity = new PublicIdentity("alice", "a", alice.kemPublicKey(), alice.signaturePublicKey());
        EncryptedPacket p = codec.decode(codec.encode(crypto.encryptSessionExchange(bob.kemPublicKey(), "bob", alice,
                "alice", "exchange", false, false, AeadAlgorithm.AES_256_GCM)));
        assertTrue(p.signed());
        assertEquals("exchange", crypto.decrypt(p, bob, identity));
        assertThrows(CryptoException.class, () -> crypto.decrypt(codec.withoutSignature(p), bob, identity));
        p.signature()[0] ^= 1;
        assertThrows(CryptoException.class, () -> crypto.decrypt(p, bob, identity));
    }

    private String decrypt(EncryptedPacket p) throws CryptoException {
        return crypto.decryptWithSession(p, p.receiver(), p.sender(), secret, p.sessionId(), p.sequence());
    }
}
