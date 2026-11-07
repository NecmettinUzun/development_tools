package tr.com.argela.nspm;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HexToPcapToolTest {
    @Test
    void parsesCommonHexFormats() {
        assertArrayEquals(
                new byte[]{0x00, 0x11, 0x22, 0x33, 0x44},
                HexToPcapTool.parseHex("0x00 11:22-33,\\x44")
        );
    }

    @Test
    void rejectsOddHexDigitCount() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> HexToPcapTool.parseHex("001")
        );

        assertEquals("Packet hex must contain an even number of hexadecimal digits.", exception.getMessage());
    }

    @Test
    void rejectsInvalidHexCharacter() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> HexToPcapTool.parseHex("00 zz")
        );

        assertEquals("Invalid hexadecimal character 'z' at position 3.", exception.getMessage());
    }

    @Test
    void createsLittleEndianPcapWithSinglePacket() {
        byte[] pcap = HexToPcapTool.convert("00 11 22 33", 1, Instant.ofEpochSecond(1_700_000_000L, 123_456_000));

        assertEquals(44, pcap.length);
        assertArrayEquals(new byte[]{(byte) 0xd4, (byte) 0xc3, (byte) 0xb2, (byte) 0xa1}, slice(pcap, 0, 4));
        assertArrayEquals(new byte[]{0x02, 0x00, 0x04, 0x00}, slice(pcap, 4, 8));
        assertEquals(65_535, readIntLE(pcap, 16));
        assertEquals(1, readIntLE(pcap, 20));
        assertEquals(1_700_000_000, readIntLE(pcap, 24));
        assertEquals(123_456, readIntLE(pcap, 28));
        assertEquals(4, readIntLE(pcap, 32));
        assertEquals(4, readIntLE(pcap, 36));
        assertArrayEquals(new byte[]{0x00, 0x11, 0x22, 0x33}, slice(pcap, 40, 44));
    }

    private static byte[] slice(byte[] values, int from, int to) {
        byte[] result = new byte[to - from];
        System.arraycopy(values, from, result, 0, result.length);
        return result;
    }

    private static int readIntLE(byte[] values, int offset) {
        return (values[offset] & 0xff)
                | ((values[offset + 1] & 0xff) << 8)
                | ((values[offset + 2] & 0xff) << 16)
                | ((values[offset + 3] & 0xff) << 24);
    }
}
