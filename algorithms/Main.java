
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        byte[] key = "secret".getBytes(StandardCharsets.UTF_8);
        DES des = new DES(key);

        String message = "Teste de mensagem.";
        byte[] ciphertext = des.Encrypt(message.getBytes(StandardCharsets.UTF_8));
        byte[] plain = des.Decrypt(ciphertext);

        System.out.println("Message: " + message);
        System.out.println("Cipher (hex): " + toHex(ciphertext));
        System.out.println("Decrypted: " + new String(plain, StandardCharsets.UTF_8));
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data)
            sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }
}
