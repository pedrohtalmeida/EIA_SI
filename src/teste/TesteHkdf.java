package teste;

import common.Chaves;
import common.Hkdf;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.HexFormat;

public class TesteHkdf {

    public static void main(String[] args) throws Exception {
        HexFormat hex = HexFormat.of();

        // 1. Vetor de teste oficial RFC 5869 - Appendix A.1 (Test Case 1 - SHA-256)
        byte[] ikm = hex.parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hex.parseHex("000102030405060708090a0b0c");
        byte[] info = hex.parseHex("f0f1f2f3f4f5f6f7f8f9");

        byte[] prkEsperado = hex.parseHex(
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] okmEsperado = hex.parseHex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        byte[] prk = Hkdf.extract(salt, ikm);
        byte[] okm = Hkdf.expand(prk, info, 42);

        if (!Arrays.equals(prk, prkEsperado)) {
            throw new AssertionError("PRK HKDF nao corresponde ao vetor RFC 5869!");
        }
        if (!Arrays.equals(okm, okmEsperado)) {
            throw new AssertionError("OKM HKDF nao corresponde ao vetor RFC 5869!");
        }

        // 2. Teste de derivacao simetrica com acordo X25519 + separacao de direcao
        KeyPair ana = Chaves.gerarParAcordo();
        KeyPair bruno = Chaves.gerarParAcordo();

        byte[] segredoAna = Chaves.segredoPartilhado(ana.getPrivate(), bruno.getPublic());
        byte[] segredoBruno = Chaves.segredoPartilhado(bruno.getPrivate(), ana.getPublic());
        byte[] saltProto = "EIA-SI-MSG-V1".getBytes(StandardCharsets.UTF_8);

        byte[] chaveAnaParaBruno1 = Hkdf.derivar(segredoAna, saltProto, "msg|ana->bruno", 32);
        byte[] chaveAnaParaBruno2 = Hkdf.derivar(segredoBruno, saltProto, "msg|ana->bruno", 32);
        byte[] chaveBrunoParaAna = Hkdf.derivar(segredoBruno, saltProto, "msg|bruno->ana", 32);

        if (!Arrays.equals(chaveAnaParaBruno1, chaveAnaParaBruno2)) {
            throw new AssertionError("Ana e Bruno derivaram chaves diferentes para o mesmo sentido!");
        }
        if (Arrays.equals(chaveAnaParaBruno1, chaveBrunoParaAna)) {
            throw new AssertionError("Sentidos opostos nao podem produzir a mesma chave!");
        }

        System.out.println("OK - TesteHkdf passou (RFC 5869 + acordo X25519 direcional).");
    }
}