import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256 {
    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder();
        for (byte hash_byte : hash) {
            String hex = Integer.toHexString(0xff & hash_byte);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static BigInteger hash(Object... input) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            for (Object i : input) {
                if (i instanceof String) {
                    sha256.update(((String) i).getBytes());
                } else if (i instanceof BigInteger) {
                    sha256.update(((BigInteger) i).toString(10).getBytes());
                } else if (i instanceof byte[]) {
                    sha256.update((byte[]) i);
                } else throw new IllegalArgumentException();
            }
            return new BigInteger(bytesToHex(sha256.digest()), 16);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return BigInteger.ZERO;
        }
    }
}