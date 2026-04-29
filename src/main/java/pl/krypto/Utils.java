package pl.krypto;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class Utils {
    public static BigInteger generateRandBigIntNumber(int bitLen, Random rand) {
        return new BigInteger(bitLen, 100, rand);
    }

    public static BigInteger generateRegularRandom(int bitLen, Random rand) {
        return new BigInteger(bitLen, rand);
    }

    public static byte[] getSHA(String format, String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(format);
        return md.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    public static BigInteger getFileHash(Path filePath) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try (InputStream is = Files.newInputStream(filePath)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }

        byte[] finalHash = digest.digest();
        return new BigInteger(1, finalHash);
    }
}
