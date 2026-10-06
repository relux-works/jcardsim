package ru.mts.bsimid.simulator;

import static org.junit.jupiter.api.Assertions.*;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.lang.reflect.Field;
import java.util.HexFormat;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.globalplatform.GPSystem;
import org.junit.jupiter.api.Test;
import ru.mts.bsimid.applet.auth.BSimAuthApplet;

/** Optional consumer integration: compile real, unchanged Auth sources; no fake channel router. */
public class BSimAuthLogicalChannelTest {
    private static final byte[] AUTH = HexFormat.of().parseHex("F00000002001");
    private static final byte[] INFO = HexFormat.of().parseHex("01f00000002001010000010003");

    private static ResponseAPDU send(CardSimulator card, int cla, int ins, int p1, int p2) {
        return card.transmitCommand(new CommandAPDU(cla, ins, p1, p2));
    }
    private static void status(int expected, ResponseAPDU answer) {
        assertEquals(expected, answer.getSW());
        if (expected != 0x9000) assertEquals(0, answer.getData().length, "refusal must export no response data");
    }
    private static void select(CardSimulator card, int channel) {
        status(0x9000, card.transmitCommand(new CommandAPDU(channel, 0xA4, 4, 0, AUTH)));
    }
    private static void info(CardSimulator card, int cla) {
        ResponseAPDU answer = card.transmitCommand(new CommandAPDU(cla, 2, 0, 0, 256));
        assertEquals(0x9000, answer.getSW());
        assertArrayEquals(INFO, answer.getData());
    }
    private static void park(CardSimulator card) {
        assertTrue(card.selectApplet(AIDUtil.create("F00000009901")));
    }
    private static CardSimulator installed() {
        CardSimulator card = new CardSimulator();
        card.installApplet(AIDUtil.create("F00000002001"), BSimAuthApplet.class);
        card.installApplet(AIDUtil.create("F00000009901"), ParkingApplet.class);
        select(card, 0);
        return card;
    }

    // Claim: actual Auth accepts B4 on basic and B5/B7 only after real open + SELECT.
    // Auth is not MultiSelectable: channels are exercised sequentially, not concurrently.
    @Test
    public void realAuthAcceptsB4B5B7OnlyOnSelectedOpenChannels() {
        CardSimulator card = installed();
        info(card, 0xB4);
        status(0x6881, send(card, 0xB6, 2, 0, 0));
        info(card, 0xB4);
        park(card);
        for (int ch : new int[]{1, 3}) {
            status(0x9000, send(card, 0, 0x70, 0, ch));
            status(0x6986, send(card, 0xB4 | ch, 2, 0, 0));
            select(card, ch);
            info(card, 0xB4 | ch);
            status(0x6E00, send(card, 0xA4 | ch, 2, 0, 0));
            info(card, 0xB4 | ch);
            status(0x9000, send(card, 0, 0x70, 0x80, ch));
            status(0x6881, send(card, 0xB4 | ch, 2, 0, 0));
        }
        select(card, 0);
        info(card, 0xB4);
    }

    // Claim: a second Auth selection is refused by runtime without disabling its first route.
    @Test
    public void realAuthCannotBeSelectedOnTwoChannelsAtOnce() {
        CardSimulator card = installed();
        status(0x9000, send(card, 0, 0x70, 0, 1));
        status(0x6985, card.transmitCommand(new CommandAPDU(1, 0xA4, 4, 0, AUTH)));
        info(card, 0xB4);
        status(0x6986, send(card, 0xB5, 2, 0, 0));
        park(card);
        select(card, 1);
        info(card, 0xB5);
    }

    // Claim: foreign/mismatched/closed-channel and unprivileged issuer commands do not
    // change the real released Core's key metadata; only issuer-authorized creation does.
    // Bound: GP authentication is the existing host fixture, not SCP cryptography or a firewall proof.
    @Test
    public void channelRefusalsPreserveKeysAndIssuerOnlyCreation() throws Exception {
        KeyVaultSimulatorPlatform platform = KeyVaultSimulatorPlatform.bootstrap();
        assertEquals(0x9000, platform.putIssuerComponent(
                1, 0, 1, AuthIssuerFixtureV1.cardIssuanceIntermediate()).status());
        AID aid = platform.installBusinessApplet("channel-auth", "F00000002001", BSimAuthApplet.class);
        CardSimulator card = platform.simulator();
        card.installApplet(AIDUtil.create("F00000009901"), ParkingApplet.class);
        assertTrue(card.selectApplet(aid));
        AuthIssuerClientV1 issuer = new AuthIssuerClientV1(card::transmitCommand);
        status(0x9000, issuer.personalizeTrustAnchor(AuthIssuerFixtureV1.canonicalAnchor()));
        Object core = platform.simulatorRuntime().appletAt(platform.coreAid());
        Object store = field(core, "store");
        byte[] empty = ((byte[])field(store, "keys")).clone();
        assertEquals(0, publishedKeys(store));
        GPSystem.setSecureChannel(null);
        status(0x6982, send(card, 0xB4, 0x56, 0, 0));
        assertArrayEquals(empty, (byte[])field(store, "keys"));
        GPSystem.setSecureChannel(new IssuerSecureChannel());
        status(0x9000, issuer.ensureKeyFootprint());
        byte[] created = ((byte[])field(store, "keys")).clone();
        assertFalse(java.util.Arrays.equals(empty, created), "authorized control actually creates keys");
        assertEquals(2, publishedKeys(store), "issuer creates exactly Kprov and AUTH keys");
        GPSystem.setSecureChannel(null);
        info(card, 0xB4);
        ResponseAPDU initialIdentity = card.transmitCommand(new CommandAPDU(0xB4, 1, 0, 0, 256));
        assertEquals(0x9000, initialIdentity.getSW());
        status(0x6881, send(card, 0xB6, 0x56, 0, 0));
        status(0x6E00, send(card, 0xA4, 2, 0, 0));
        park(card);
        status(0x9000, send(card, 0, 0x70, 0, 1));
        select(card, 1);
        info(card, 0xB5);
        status(0x6982, send(card, 0xB5, 0x56, 0, 0));
        status(0x6E00, send(card, 0xA5, 2, 0, 0));
        status(0x6E00, send(card, 0xFF, 2, 0, 0));
        status(0x9000, send(card, 0, 0x70, 0, 2));
        status(0x6986, send(card, 0xB6, 0x56, 0, 0));
        info(card, 0xB5);
        // The identity response is the public record, not a private-key export.
        ResponseAPDU identity = card.transmitCommand(new CommandAPDU(0xB5, 1, 0, 0, 256));
        assertEquals(0x9000, identity.getSW());
        assertEquals(127, identity.getData().length);
        assertEquals(0x30, identity.getData()[0] & 255, "record starts with public SPKI");
        assertArrayEquals(java.security.MessageDigest.getInstance("SHA-256").digest(
                java.util.Arrays.copyOf(identity.getData(), 91)),
                java.util.Arrays.copyOfRange(identity.getData(), 91, 123));
        assertArrayEquals(initialIdentity.getData(), identity.getData(), "refusals must not rotate key material");
        status(0x6D00, send(card, 0xB5, 3, 0, 0));
        status(0x9000, send(card, 0, 0x70, 0x80, 1));
        status(0x6881, send(card, 0xB5, 0x56, 0, 0));
        assertArrayEquals(created, (byte[])field(store, "keys"));
        assertEquals(2, publishedKeys(store), "refusals create no additional keys");
        select(card, 0);
        info(card, 0xB4);
    }

    private static int publishedKeys(Object store) throws Exception {
        byte[] keys = (byte[])field(store, "keys");
        int row = ((Number)field(store, "KEY_ROW")).intValue();
        int used = ((Number)field(store, "KEY_USED")).intValue();
        int published = ((Number)field(store, "KEY_PUBLISHED")).intValue();
        int count = 0;
        for (int at = used; at < keys.length; at += row) if (keys[at] == published) count++;
        return count;
    }

    private static Object field(Object owner, String name) throws Exception {
        Field field = owner.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(owner);
    }

    public static class ParkingApplet extends Applet {
        public static void install(byte[] b, short o, byte l) { new ParkingApplet().register(); }
        public void process(APDU apdu) {
            if (!selectingApplet()) ISOException.throwIt((short) 0x6D00);
        }
    }
}
