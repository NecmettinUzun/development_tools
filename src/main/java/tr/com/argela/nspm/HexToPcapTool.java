package tr.com.argela.nspm;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.HexFormat;

final class HexToPcapTool {
    private static final int PCAP_SNAP_LEN = 65_535;

    private HexToPcapTool() {
    }

    static byte[] convert(String hex, int linkType, Instant timestamp) {
        byte[] packet = parseHex(hex);
        if (packet.length > PCAP_SNAP_LEN) {
            throw new IllegalArgumentException("Packet is larger than the PCAP snap length of " + PCAP_SNAP_LEN + " bytes.");
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream(24 + 16 + packet.length);
        writeIntLE(output, 0xa1b2c3d4);
        writeShortLE(output, 2);
        writeShortLE(output, 4);
        writeIntLE(output, 0);
        writeIntLE(output, 0);
        writeIntLE(output, PCAP_SNAP_LEN);
        writeIntLE(output, linkType);

        writeIntLE(output, Math.toIntExact(timestamp.getEpochSecond()));
        writeIntLE(output, timestamp.getNano() / 1_000);
        writeIntLE(output, packet.length);
        writeIntLE(output, packet.length);
        output.writeBytes(packet);
        return output.toByteArray();
    }

    static byte[] parseHex(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Packet hex is required.");
        }

        String normalized = input
                .replaceAll("(?i)0x", "")
                .replaceAll("(?i)\\\\x", "")
                .replaceAll("[\\s,:;_|-]", "");

        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Packet hex is required.");
        }
        if ((normalized.length() & 1) == 1) {
            throw new IllegalArgumentException("Packet hex must contain an even number of hexadecimal digits.");
        }

        for (int index = 0; index < normalized.length(); index++) {
            char value = normalized.charAt(index);
            if (Character.digit(value, 16) == -1) {
                throw new IllegalArgumentException("Invalid hexadecimal character '" + value + "' at position " + (index + 1) + ".");
            }
        }

        return HexFormat.of().parseHex(normalized);
    }

    private static void writeShortLE(ByteArrayOutputStream output, int value) {
        output.write(value & 0xff);
        output.write((value >>> 8) & 0xff);
    }

    private static void writeIntLE(ByteArrayOutputStream output, int value) {
        output.write(value & 0xff);
        output.write((value >>> 8) & 0xff);
        output.write((value >>> 16) & 0xff);
        output.write((value >>> 24) & 0xff);
    }
}
