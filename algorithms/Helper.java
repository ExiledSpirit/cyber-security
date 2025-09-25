import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

public class Helper {
    public static String utfToBin(String utf) {
		
		// Convert to binary
		byte[] bytes = null;
		try {
			bytes = utf.getBytes();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String bin = "";
		for (int i = 0; i < bytes.length; i++) {
		     int value = bytes[i];
		     for (int j = 0; j < 8; j++)
		     {
		        bin += ((value & 128) == 0 ? 0 : 1);
		        value <<= 1;
		     }
		}
		return bin;
    }

    public static String binToHex(String bin) {
		BigInteger b = new BigInteger(bin, 2);
		String ciphertext = b.toString(16);
		
		return ciphertext;
    }

    public static String toHex(String arg) {
        try {
            return String.format("%040x", new BigInteger(1, arg.getBytes("utf-8")));
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return arg;
    }
	
    public static String byteArrayToBinaryString(byte[] byteArray) {
        StringBuilder binaryString = new StringBuilder();
        for (byte b : byteArray) {
            // Convert each byte to an 8-bit binary string
            String binary = String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
            binaryString.append(binary);
        }
        return binaryString.toString();
    }
}
