public class Main {
    public static void main(String[] args) {
        DES des = new DES("key".getBytes());
        String message = "message";

        des.Encrypt(message.getBytes());
        System.out.println("Message: " + message);
        System.out.println("Binary: " + Helper.utfToBin(message));
        System.out.println("Hex: " + Helper.toHex(message));
    }
}
