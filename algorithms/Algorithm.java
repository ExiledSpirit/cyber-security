public interface Algorithm {
    byte[] Encrypt(byte[] decrypted);
    byte[] Decrypt(byte[] encrypted);
}
