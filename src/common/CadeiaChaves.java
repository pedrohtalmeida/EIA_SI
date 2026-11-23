package common;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Cadeia de chaves simétrica unidirecional (Ratchet simples - Módulo B).
 *
 * - Chave de cadeia inicial CK_0 derivada por X25519 + HKDF-SHA256.
 * - A cada passo n:
 *     MK_n     = HKDF-Expand(CK_n, "msg-key",   32)  (chave da mensagem n)
 *     CK_{n+1} = HKDF-Expand(CK_n, "chain-key", 32)  (próxima chave de cadeia)
 *   e CK_n é imediatamente apagada da memória (Arrays.fill).
 * - Suporta mensagens fora de ordem até LIMITE_SALTADAS (50) chaves guardadas.
 */
public final class CadeiaChaves {

    public static final int LIMITE_SALTADAS = 50;
    private static final int TAMANHO_CHAVE = 32;
    private static final byte[] SALT_INICIAL = "EIA-SI-RATCHET-V1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INFO_MSG_KEY = "msg-key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INFO_CHAIN_KEY = "chain-key".getBytes(StandardCharsets.UTF_8);

    private final long idSessao;
    private final byte[] chaveCadeia; // CK_atual (32 bytes)
    private long proximoContador;
    private final Map<Long, byte[]> chavesSaltadas = new HashMap<>();

    private CadeiaChaves(long idSessao, byte[] chaveCadeiaInicial) {
        this.idSessao = idSessao;
        this.chaveCadeia = chaveCadeiaInicial;
        this.proximoContador = 0;
    }

    /**
     * Cria uma nova cadeia de envio com um idSessao aleatório.
     */
    public static CadeiaChaves criarParaEnvio(PrivateKey meuAcordo, PublicKey acordoOutro,
                                              String remetente, String destinatario)
            throws GeneralSecurityException {
        long idSessao = new SecureRandom().nextLong();
        return criarComSessao(idSessao, meuAcordo, acordoOutro, remetente, destinatario);
    }

    /**
     * Cria ou reinicializa uma cadeia de receção para um idSessao específico.
     */
    public static CadeiaChaves criarComSessao(long idSessao, PrivateKey meuAcordo, PublicKey acordoOutro,
                                              String remetente, String destinatario)
            throws GeneralSecurityException {
        byte[] segredo = Chaves.segredoPartilhado(meuAcordo, acordoOutro);
        try {
            byte[] salt = ByteBuffer.allocate(SALT_INICIAL.length + Long.BYTES)
                    .put(SALT_INICIAL)
                    .putLong(idSessao)
                    .array();
            String contexto = "ratchet|" + remetente + "->" + destinatario;
            byte[] ck0 = Hkdf.derivar(segredo, salt, contexto, TAMANHO_CHAVE);
            return new CadeiaChaves(idSessao, ck0);
        } finally {
            Arrays.fill(segredo, (byte) 0);
        }
    }

    public long getIdSessao() {
        return idSessao;
    }

    public synchronized long getProximoContador() {
        return proximoContador;
    }

    public synchronized int getTotalSaltadas() {
        return chavesSaltadas.size();
    }

    /**
     * Devolve cópia da chave de cadeia atual (apenas para testes de segurança).
     */
    public synchronized byte[] copiarChaveCadeiaAtualParaTeste() {
        return Arrays.copyOf(chaveCadeia, chaveCadeia.length);
    }

    /**
     * Remetente: obtém a chave da próxima mensagem e avança a cadeia, apagando a anterior.
     */
    public synchronized PassoEnvio avancarParaEnvio() throws GeneralSecurityException {
        long contadorAtual = proximoContador;
        byte[] chaveMensagem = avancarUmPasso();
        return new PassoEnvio(idSessao, contadorAtual, chaveMensagem);
    }

    /**
     * Destinatário: obtém a chave para o contador recebido.
     * - Rejeita mensagens repetidas (contador já consumido).
     * - Guarda chaves saltadas se chegar fora de ordem, até LIMITE_SALTADAS.
     */
    public synchronized byte[] obterChaveParaRececao(long contadorRecebido) throws GeneralSecurityException {
        if (contadorRecebido < 0) {
            throw new GeneralSecurityException("Contador de mensagem negativo.");
        }

        // 1. Verificar se é uma mensagem atrasada cuja chave ficou guardada
        byte[] saltada = chavesSaltadas.remove(contadorRecebido);
        if (saltada != null) {
            return saltada;
        }

        // 2. Se for menor que o próximo contador esperado e não estava nas saltadas -> repetida
        if (contadorRecebido < proximoContador) {
            throw new GeneralSecurityException("Mensagem repetida ou ja consumida (contador " + contadorRecebido + ").");
        }

        // 3. Verificar o limite de chaves a saltar para evitar DoS em memória
        long aSaltar = contadorRecebido - proximoContador;
        if (aSaltar > LIMITE_SALTADAS || (chavesSaltadas.size() + aSaltar) > LIMITE_SALTADAS) {
            throw new GeneralSecurityException(
                    "Limite de mensagens fora de ordem excedido (maximo " + LIMITE_SALTADAS + ").");
        }

        // 4. Avançar e guardar as chaves intermédias saltadas
        while (proximoContador < contadorRecebido) {
            long c = proximoContador;
            byte[] mkSaltada = avancarUmPasso();
            chavesSaltadas.put(c, mkSaltada);
        }

        // 5. Devolver a chave do contador exato e avançar a cadeia
        return avancarUmPasso();
    }

    /**
     * Deriva MK_n e CK_{n+1} a partir de CK_n e destrói CK_n imediatamente.
     */
    private byte[] avancarUmPasso() throws GeneralSecurityException {
        byte[] mk = Hkdf.expand(chaveCadeia, INFO_MSG_KEY, TAMANHO_CHAVE);
        byte[] proximaCk = Hkdf.expand(chaveCadeia, INFO_CHAIN_KEY, TAMANHO_CHAVE);

        // Apaga a chave de cadeia anterior da memória (Forward Secrecy)
        Arrays.fill(chaveCadeia, (byte) 0);
        System.arraycopy(proximaCk, 0, chaveCadeia, 0, TAMANHO_CHAVE);
        Arrays.fill(proximaCk, (byte) 0);

        proximoContador++;
        return mk;
    }

    /**
     * Limpa todo o estado sensível da cadeia da memória.
     */
    public synchronized void destruir() {
        Arrays.fill(chaveCadeia, (byte) 0);
        for (byte[] mk : chavesSaltadas.values()) {
            Arrays.fill(mk, (byte) 0);
        }
        chavesSaltadas.clear();
    }

    public static final class PassoEnvio {
        public final long idSessao;
        public final long contador;
        public final byte[] chaveMensagem;

        public PassoEnvio(long idSessao, long contador, byte[] chaveMensagem) {
            this.idSessao = idSessao;
            this.contador = contador;
            this.chaveMensagem = chaveMensagem;
        }
    }
}