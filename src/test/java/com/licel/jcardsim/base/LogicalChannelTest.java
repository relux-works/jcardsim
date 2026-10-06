package com.licel.jcardsim.base;

import com.licel.jcardsim.utils.AIDUtil;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.MultiSelectable;
import junit.framework.TestCase;

/** Channel routing claims drive Simulator.transmitCommand, never the CLA decoder alone. */
public class LogicalChannelTest extends TestCase {
    private Simulator simulator;
    private final AID first = AIDUtil.create("F00000000101");
    private final AID second = AIDUtil.create("F00000000201");

    protected void setUp() {
        simulator = new Simulator();
        simulator.installApplet(first, ProbeApplet.class);
        simulator.installApplet(second, ProbeApplet.class);
        ProbeApplet.calls = 0;
        ProbeApplet.multiSelects = 0;
        ProbeApplet.multiDeselects = 0;
        ProbeApplet.rejectSelect = false;
    }

    private byte[] command(int... bytes) {
        byte[] command = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) command[i] = (byte) bytes[i];
        return simulator.transmitCommand(command);
    }

    private void sw(int status, int... bytes) {
        byte[] response = command(bytes);
        assertEquals(status, ((response[response.length - 2] & 255) << 8)
                | (response[response.length - 1] & 255));
    }

    private void select(int cla, AID aid) {
        byte[] value = new byte[16];
        int length = aid.getBytes(value, (short) 0);
        int[] bytes = new int[5 + length];
        bytes[0] = cla; bytes[1] = 0xA4; bytes[2] = 4; bytes[4] = length;
        for (int i = 0; i < length; i++) bytes[5 + i] = value[i] & 255;
        sw(0x9000, bytes);
    }

    private void echo(int cla, int channel, int value) {
        assertTrue(Arrays.equals(new byte[]{(byte) cla, (byte) channel, (byte) channel,
                        (byte) value, 1, (byte) 0x90, 0}, command(cla, 0x02, 0, 0, 5)));
    }

    // Claim: B6 after a basic-channel SELECT is 6881 and never executes the applet.
    // Positive control: B4 reaches the same applet with its original CLA and channel 0.
    public void testB6CannotReachBasicChannelSelection() {
        select(0, first);
        echo(0xB4, 0, 0);
        int calls = ProbeApplet.calls;
        sw(0x6881, 0xB6, 0x01, 0x55, 0);
        assertEquals(calls, ProbeApplet.calls);
        echo(0xB4, 0, 0);
    }

    // Claim: opening a channel does not borrow channel 0's selected applet.
    public void testOpenUnselectedChannelCannotBorrowSelection() {
        select(0, first);
        sw(0x9000, 0, 0x70, 0, 2);
        echo(0xB4, 0, 0);
        int calls = ProbeApplet.calls;
        sw(0x6986, 0xB6, 0x01, 0x55, 0);
        assertEquals(calls, ProbeApplet.calls);
        select(2, second);
        echo(0xB6, 2, 0);
    }

    // Claim: first-encoding channels 1..3 select independently and retain state per applet.
    public void testFirstEncodingSelectAndRouteEveryChannel() {
        select(0, first);
        for (int ch = 1; ch <= 3; ch++) {
            sw(0x9000, 0, 0x70, 0, ch);
            select(ch, first);
            sw(0x9000, 0xB4 | ch, 1, ch, 0);
            echo(0xB4 | ch, ch, ch);
            sw(0x9000, 0, 0x70, 0x80, ch);
        }
        echo(0xB4, 0, 3);
    }

    // Claim: further encoding selects/routes 4..19 (FF alone is reserved; CF codes 19).
    public void testFurtherEncodingSelectAndRouteEveryChannel() {
        for (int ch = 4; ch <= 19; ch++) {
            sw(0x9000, 0, 0x70, 0, ch);
            select(0x40 | (ch - 4), first);
            int cla = ch == 19 ? 0xCF : 0xF0 | (ch - 4);
            sw(0x9000, cla, 1, ch, 0);
            echo(cla, ch, ch);
            sw(0x9000, 0, 0x70, 0x80, ch);
            sw(0x6881, cla, 1, 0x55, 0);
        }
    }

    // Claim: closing removes routing; reopening still requires SELECT and clears COD state.
    public void testCloseAndReopenNeverRestoresSelection() {
        sw(0x9000, 0, 0x70, 0, 2);
        select(2, first);
        sw(0x9000, 0xB6, 1, 0x55, 0);
        echo(0xB6, 2, 0x55);
        sw(0x9000, 0, 0x70, 0x80, 2);
        int calls = ProbeApplet.calls;
        sw(0x6881, 0xB6, 1, 0x66, 0);
        assertEquals(calls, ProbeApplet.calls);
        sw(0x9000, 0, 0x70, 0, 2);
        sw(0x6986, 0xB6, 1, 0x66, 0);
        assertEquals(calls, ProbeApplet.calls);
        select(2, first);
        echo(0xB6, 2, 0);
    }

    // Claim: FF is rejected even when channel 19 is open and selected; CF remains valid.
    public void testReservedFFDoesNotReachSelectedChannel19() {
        sw(0x9000, 0, 0x70, 0, 19);
        select(0x4F, first);
        echo(0xCF, 19, 0);
        int calls = ProbeApplet.calls;
        sw(0x6E00, 0xFF, 1, 0x55, 0);
        assertEquals(calls, ProbeApplet.calls);
        echo(0xCF, 19, 0);
    }

    // Claim: duplicate/out-of-range opens and basic/unopened closes preserve valid routes.
    public void testManageChannelRejectsInvalidTargetsWithoutChangingState() {
        select(0, first);
        sw(0x9000, 0, 0x70, 0, 1);
        select(1, second);
        sw(0x6A86, 0, 0x70, 0, 1);
        sw(0x6A86, 0, 0x70, 0, 20);
        sw(0x6A86, 0, 0x70, 0x80, 20);
        sw(0x6A81, 0, 0x70, 0x80, 0);
        sw(0x6881, 0, 0x70, 0x80, 2);
        sw(0x6A86, 0, 0x70, 1, 2);
        echo(0xB4, 0, 0);
        echo(0xB5, 1, 0);
    }

    // Claim: MANAGE CHANNEL refuses SM, chaining and data; targets stay unopened.
    public void testManageChannelRejectsUnsupportedFraming() {
        sw(0x6882, 0x0C, 0x70, 0, 1);
        sw(0x6884, 0x10, 0x70, 0, 1);
        sw(0x6700, 0, 0x70, 0, 1, 1, 0);
        sw(0x6700, 0, 0x70, 0, 1, 1);
        sw(0x6700, 0, 0x70, 0, 0);
        sw(0x6881, 0xB5, 1, 0, 0);
        sw(0x9000, 0, 0x70, 0, 1);
        select(1, first);
        echo(0xB5, 1, 0);
    }

    // Claim: automatic open allocates 1..19, exhaustion refuses, and reuse selects lowest free.
    public void testAutomaticOpenExhaustionAndReuse() {
        for (int ch = 1; ch <= 19; ch++) {
            assertTrue(Arrays.equals(new byte[]{(byte) ch, (byte) 0x90, 0}, command(0, 0x70, 0, 0, 1)));
        }
        sw(0x6A81, 0, 0x70, 0, 0, 1);
        sw(0x9000, 0, 0x70, 0x80, 3);
        assertTrue(Arrays.equals(new byte[]{3, (byte) 0x90, 0}, command(0, 0x70, 0, 0, 1)));
    }

    // Claim: a proprietary INS 70 belongs to the applet, not runtime MANAGE CHANNEL.
    public void testProprietaryManageInstructionRemainsAppletCommand() {
        select(0, first);
        sw(0x6D00, 0xB4, 0x70, 0, 1);
        sw(0x6881, 0xB5, 1, 0, 0);
        sw(0x9000, 0, 0x70, 0, 1);
        select(1, first);
        echo(0xB5, 1, 0);
    }

    // Claim: a non-MultiSelectable applet cannot be selected twice; original route survives.
    public void testNonMultiselectableSecondSelectionIsRejected() {
        AID single = AIDUtil.create("F00000000301");
        simulator.installApplet(single, SingleApplet.class);
        select(0, single);
        sw(0x9000, 0, 0x70, 0, 1);
        sw(0x6985, 1, 0xA4, 4, 0, 6, 0xF0, 0, 0, 0, 3, 1);
        sw(0x6986, 0xB5, 1, 0, 0);
        sw(0x9000, 0xB4, 1, 0, 0);
        select(0, first);
        select(1, single);
        sw(0x9000, 0xB5, 1, 0, 0);
    }

    // Claim: deselecting another applet does not clear this applet's COD arrays.
    public void testDeselectDoesNotClearAnotherChannelsTransientState() {
        select(0, first);
        sw(0x9000, 0, 0x70, 0, 1);
        select(1, second);
        sw(0x9000, 0xB5, 1, 0x55, 0);
        select(0, second);
        echo(0xB5, 1, 0x55);
        assertEquals(1, ProbeApplet.multiSelects);
        select(0, first);
        echo(0xB5, 1, 0x55);
        assertEquals(1, ProbeApplet.multiDeselects);
        sw(0x9000, 0, 0x70, 0x80, 1);
        sw(0x9000, 0, 0x70, 0, 1);
        select(1, second);
        echo(0xB5, 1, 0);
    }

    // Claim: failed select cannot leave an authorized route to the refusing instance.
    public void testFailedSelectLeavesChannelUnselected() {
        sw(0x9000, 0, 0x70, 0, 1);
        ProbeApplet.rejectSelect = true;
        sw(0x6999, 1, 0xA4, 4, 0, 6, 0xF0, 0, 0, 0, 1, 1);
        sw(0x6986, 0xB5, 1, 0x55, 0);
        ProbeApplet.rejectSelect = false;
        select(1, first);
        echo(0xB5, 1, 0);
    }

    // Claim: closing via P2=0 closes the originating logical channel, never channel 0.
    public void testCloseOriginChannel() {
        select(0, first);
        sw(0x9000, 0, 0x70, 0, 3);
        select(3, second);
        sw(0x9000, 3, 0x70, 0x80, 0);
        sw(0x6881, 0xB7, 1, 0x55, 0);
        echo(0xB4, 0, 0);
    }

    // Claim: reset closes logical channels, clears selections and COD state; channel 0 reselects.
    public void testResetClosesChannelsAndClearsSelections() {
        sw(0x9000, 0, 0x70, 0, 1);
        select(1, first);
        sw(0x9000, 0xB5, 1, 0x55, 0);
        simulator.reset();
        sw(0x6881, 0xB5, 1, 0x66, 0);
        sw(0x6986, 0xB4, 1, 0x66, 0);
        select(0, first);
        echo(0xB4, 0, 0);
    }

    public static class ProbeApplet extends Applet implements MultiSelectable {
        static int calls, multiSelects, multiDeselects;
        static boolean rejectSelect;
        private final byte[] state = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        public static void install(byte[] data, short offset, byte length) { new ProbeApplet().register(); }
        public boolean select() { return !rejectSelect; }
        public boolean select(boolean active) { multiSelects++; return !rejectSelect; }
        public void deselect(boolean active) { multiDeselects++; }
        public void process(APDU apdu) {
            if (selectingApplet()) return;
            calls++;
            byte[] b = apdu.getBuffer();
            if (b[1] == 1) { state[0] = b[2]; return; }
            if (b[1] != 2) ISOException.throwIt((short) 0x6D00);
            byte cla = b[0];
            b[0] = cla;
            b[1] = APDU.getCLAChannel();
            b[2] = JCSystem.getAssignedChannel();
            b[3] = state[0];
            b[4] = (byte) (JCSystem.isAppletActive(JCSystem.getAID()) ? 1 : 0);
            apdu.setOutgoingAndSend((short) 0, (short) 5);
        }
    }

    public static class SingleApplet extends Applet {
        public static void install(byte[] data, short offset, byte length) { new SingleApplet().register(); }
        public void process(APDU apdu) { }
    }
}
