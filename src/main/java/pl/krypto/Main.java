package pl.krypto;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import static pl.krypto.Utils.*;

public class Main {
    public record InitParameters(BigInteger p, BigInteger q, BigInteger h, BigInteger a, BigInteger b) {}
    public record DocumentSignature(BigInteger s1, BigInteger s2) {}

    public static Random random = new Random();

    public static InitParameters GenerateKeys(int qBitLen, int pBitLen) {
        int kBitLen = pBitLen - qBitLen;

        BigInteger q = generateRandBigIntNumber(qBitLen, random);

        BigInteger p;

        BigInteger kMin = BigInteger.TWO.pow(pBitLen - 1).divide(q);
        BigInteger kMax = BigInteger.TWO.pow(pBitLen).subtract(BigInteger.ONE).divide(q);
        BigInteger range = kMax.subtract(kMin);
        BigInteger k;

        BigInteger h;
        BigInteger g;

        do {
            k = new BigInteger(range.bitLength(), random).mod(range).add(kMin);

            p = k.multiply(q).add(BigInteger.ONE);

        } while (p.bitLength() != pBitLen || !p.isProbablePrime(100));

        do {
            g = new BigInteger(pBitLen, random).mod(p.subtract(BigInteger.TWO)).add(BigInteger.TWO);
            h = g.modPow((p.subtract(BigInteger.ONE).divide(q)), p);
        } while (h.equals(BigInteger.ONE));

        BigInteger a;

        do {
            a = new BigInteger(qBitLen, random);
        } while (a.equals(BigInteger.ZERO) || a.compareTo(q) >= 0);

        BigInteger b = h.modPow(a, p);

        return new InitParameters(p, q, h, a, b);
    }

    public static DocumentSignature GenerateSignature(BigInteger p, BigInteger q, BigInteger h, BigInteger a, BigInteger fM) throws NoSuchAlgorithmException {
        int qBitLen = q.bitLength();

        BigInteger r = generateRegularRandom(qBitLen - 1, random);
        BigInteger rDiff = r.modInverse(q);

        BigInteger s1 = h.modPow(r, p).mod(q);

        BigInteger s2 = rDiff.multiply(fM.add(a.multiply(s1))).mod(q);

        return new DocumentSignature(s1, s2);
    }

    public static boolean VerifySignature(BigInteger s1, BigInteger s2, BigInteger q, BigInteger p, BigInteger h, BigInteger b, BigInteger fM) throws NoSuchAlgorithmException {
        BigInteger sDiff = s2.modInverse(q);

        BigInteger u1 = fM.multiply(sDiff).mod(q);
        BigInteger u2 = sDiff.multiply(s1).mod(q);

        BigInteger hu1 = h.modPow(u1, p);
        BigInteger bu2 = b.modPow(u2, p);
        BigInteger t =  hu1.multiply(bu2).mod(p).mod(q);

        return t.equals(s1);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {

    }
}
