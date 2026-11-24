package common;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Hkdf {

    private static final String ALGORITMO_HMAC = "HmacSHA256";
    private static final int TAMANHO_HASH = 32; // SHA-256 = 32 bytes

    private Hkdf() {
    }

    /**
     * Passo Extract do RFC 5869: PRK = HMAC-Hash(salt, IKM).
     */
    public static byte[] extract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        if (ikm == null || ikm.length == 0) {
            throw new IllegalArgumentException("IKM não pode ser nulo nem vazio.");
        }
        byte[] saltEfetivo = (salt == null || salt.length == 0) ? new byte[TAMANHO_HASH] : salt;
        Mac mac = Mac.getInstance(ALGORITMO_HMAC);
        mac.init(new SecretKeySpec(saltEfetivo, ALGORITMO_HMAC));
        return mac.doFinal(ikm);
    }

    /**
     * Passo Expand do RFC 5869: deriva OKM com o tamanho pretendido (em bytes).
     */
    public static byte[] expand(byte[] prk, byte[] info, int tamanhoSaida) throws GeneralSecurityException {
        if (prk == null || prk.length < TAMANHO_HASH) {
            throw new IllegalArgumentException("PRK inválido (mínimo 32 bytes).");
        }
        if (tamanhoSaida <= 0 || tamanhoSaida > 255 * TAMANHO_HASH) {
            throw new IllegalArgumentException("Tamanho de saída HKDF inválido: " + tamanhoSaida);
        }

        byte[] infoEfetivo = (info == null) ? new byte[0] : info;
        int n = (int) Math.ceil((double) tamanhoSaida / TAMANHO_HASH);
        byte[] okm = new byte[tamanhoSaida];
        byte[] tAnterior = new byte[0];
        int offset = 0;

        Mac mac = Mac.getInstance(ALGORITMO_HMAC);
        mac.init(new SecretKeySpec(prk, ALGORITMO_HMAC));

        for (int i = 1; i <= n; i++) {
            mac.reset();
            mac.update(tAnterior);
            mac.update(infoEfetivo);
            mac.update((byte) i);
            byte[] tAtual = mac.doFinal();

            int aCopiar = Math.min(TAMANHO_HASH, tamanhoSaida - offset);
            System.arraycopy(tAtual, 0, okm, offset, aCopiar);
            offset += aCopiar;

            Arrays.fill(tAnterior, (byte) 0);
            tAnterior = tAtual;
        }
        Arrays.fill(tAnterior, (byte) 0);
        return okm;
    }

    /**
     * Atalho Extract + Expand num único passo.
     */
    public static byte[] derivar(byte[] ikm, byte[] salt, String contexto, int tamanhoSaida)
            throws GeneralSecurityException {
        byte[] info = (contexto == null) ? new byte[0] : contexto.getBytes(StandardCharsets.UTF_8);
        byte[] prk = extract(salt, ikm);
        try {
            return expand(prk, info, tamanhoSaida);
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }
}