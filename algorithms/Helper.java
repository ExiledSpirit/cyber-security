
import java.nio.charset.StandardCharsets;

public class Helper {
    public static String utfToBin(String utf) {
        byte[] bytes = utf.getBytes(StandardCharsets.UTF_8);
        return byteArrayToBinaryString(bytes);
    }

    public static String toHex(String utf) {
        byte[] bytes = utf.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }

    public static String byteArrayToBinaryString(byte[] byteArray) {
        StringBuilder binaryString = new StringBuilder();
        for (byte b : byteArray) {
            String binary = String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', "0".charAt(0));
            binaryString.append(binary);
        }
        return binaryString.toString();
    }
}
