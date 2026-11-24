package client;

import common.Bytes;
import common.Hkdf;
import common.Registo;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Módulo A — Confiança na primeira utilização (TOFU) e verificação de impressões digitais.
 *
 * - Guarda localmente em ficheiro (dados/<nome>.contactos) as impressões digitais SHA-256
 *   das chaves públicas (Ed25519 + X25519) dos contactos conhecidos.
 * - Integridade protegida por HMAC-SHA256 com chave derivada da identidade privada via HKDF.
 * - Bloqueia o envio ou receção se a chave de um contacto conhecido mudar.
 * - Gera um código curto de verificação (12 dígitos) para confirmação fora de banda.
 */
public final class Contactos {

    private static final byte[] CABECALHO_FICHEIRO = "EIASICONTACTOS1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SALT_HMAC = "EIA-SI-CONTACTOS-HMAC-V1".getBytes(StandardCharsets.UTF_8);
    private static final int TAM_HASH = 32; // SHA-256

    private final Path ficheiro;
    private final byte[] chaveHmac;
    private final Map<String, byte[]> impressoesDigitais = new LinkedHashMap<>();

    private Contactos(Path ficheiro, byte[] chaveHmac) {
        this.ficheiro = ficheiro;
        this.chaveHmac = chaveHmac;
    }

    /**
     * Carrega o ficheiro de contactos (verificando o HMAC) ou inicializa um vazio se ainda não existir.
     */
    public static Contactos carregar(Path ficheiro, Identidade identidade)
            throws IOException, GeneralSecurityException {
        byte[] ikm = identidade.getAssinaturaEd25519().getPrivate().getEncoded();
        byte[] chaveHmac;
        try {
            chaveHmac = Hkdf.derivar(ikm, SALT_HMAC, "contactos-hmac|" + identidade.getNome(), TAM_HASH);
        } finally {
            Arrays.fill(ikm, (byte) 0);
        }

        Contactos gestor = new Contactos(ficheiro, chaveHmac);
        if (Files.exists(ficheiro)) {
            gestor.lerEVerificar();
        }
        return gestor;
    }

    /**
     * Calcula a impressão digital SHA-256 da identidade pública completa de um Registo
     * (nome + chave pública Ed25519 + chave pública X25519).
     */
   public static byte[] calcularImpressaoDigital(Registo registo)
            throws IOException, GeneralSecurityException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(buffer);
        d.writeUTF(registo.nome);
        Bytes.escrever(d, registo.chaveAssinatura.getEncoded());
        Bytes.escrever(d, registo.chaveAcordo.getEncoded());

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(buffer.toByteArray());
    }
    /**
     * Gera um código curto de 12 dígitos agrupados (ex.: 1234-5678-9012) a partir da impressão digital,
     * para os dois utilizadores compararem por telefone / fora de banda.
     */
    public static String gerarCodigoVerificacao(byte[] impressaoDigital) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("EIA-SI-CODIGO-VERIFICACAO-V1".getBytes(StandardCharsets.UTF_8));
        byte[] resumo = md.digest(impressaoDigital);

        ByteBuffer bb = ByteBuffer.wrap(resumo);
        int g1 = Math.floorMod(bb.getInt(), 10000);
        int g2 = Math.floorMod(bb.getInt(), 10000);
        int g3 = Math.floorMod(bb.getInt(), 10000);
        return String.format("%04d-%04d-%04d", g1, g2, g3);
    }

    /**
     * Verifica um registo segundo a política TOFU:
     * - Se for a primeira vez que vemos este contacto: guarda a impressão digital em disco e devolve true.
     * - Se já era conhecido e a chave mantém-se igual: devolve false.
     * - Se a chave mudou: lança GeneralSecurityException para bloquear envio/receção.
     */
    public synchronized boolean verificarOuRegistarTofu(Registo registo)
            throws IOException, GeneralSecurityException {
        byte[] novaFp = calcularImpressaoDigital(registo);
        byte[] guardada = impressoesDigitais.get(registo.nome);

        if (guardada == null) {
            impressoesDigitais.put(registo.nome, novaFp);
            guardar();
            return true; // Primeira utilização (TOFU)
        }

        if (!MessageDigest.isEqual(guardada, novaFp)) {
            String codAntigo = gerarCodigoVerificacao(guardada);
            String codNovo = gerarCodigoVerificacao(novaFp);
            throw new GeneralSecurityException(
                    "ALERTA DE SEGURANCA (TOFU): A chave publica de '" + registo.nome + "' MUDOU!\n"
                    + "  Codigo anterior : " + codAntigo + "\n"
                    + "  Codigo recebido : " + codNovo + "\n"
                    + "  Operacao bloqueada para prevenir ataque Man-in-the-Middle.");
        }

        return false;
    }

    /**
     * Devolve o código curto de verificação de um contacto já conhecido, ou null se ainda não existir.
     */
    public synchronized String obterCodigoVerificacao(String nomeContacto) throws GeneralSecurityException {
        byte[] fp = impressoesDigitais.get(nomeContacto);
        if (fp == null) {
            return null;
        }
        return gerarCodigoVerificacao(fp);
    }

    public synchronized Map<String, byte[]> listarImpressoes() {
        return Collections.unmodifiableMap(impressoesDigitais);
    }

    private void lerEVerificar() throws IOException, GeneralSecurityException {
        byte[] total = Files.readAllBytes(ficheiro);
        if (total.length < CABECALHO_FICHEIRO.length + TAM_HASH) {
            throw new GeneralSecurityException("Ficheiro de contactos corrompido ou truncado.");
        }

        int posHmac = total.length - TAM_HASH;
        byte[] payload = Arrays.copyOfRange(total, 0, posHmac);
        byte[] hmacLido = Arrays.copyOfRange(total, posHmac, total.length);
        byte[] hmacCalculado = calcularHmac(payload);

        if (!MessageDigest.isEqual(hmacLido, hmacCalculado)) {
            throw new GeneralSecurityException(
                    "ALERTA DE INTEGRIDADE: O ficheiro de contactos '" + ficheiro + "' foi adulterado!");
        }

        DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload));
        byte[] cabecalho = new byte[CABECALHO_FICHEIRO.length];
        in.readFully(cabecalho);
        if (!Arrays.equals(cabecalho, CABECALHO_FICHEIRO)) {
            throw new GeneralSecurityException("Formato invalido do ficheiro de contactos.");
        }

        int quantidade = in.readInt();
        if (quantidade < 0 || quantidade > 10_000) {
            throw new GeneralSecurityException("Numero de contactos invalido no ficheiro.");
        }

        impressoesDigitais.clear();
        for (int i = 0; i < quantidade; i++) {
            String nomeContacto = in.readUTF();
            byte[] fp = Bytes.ler(in, TAM_HASH);
            if (fp.length != TAM_HASH) {
                throw new GeneralSecurityException("Impressao digital com tamanho invalido.");
            }
            impressoesDigitais.put(nomeContacto, fp);
        }

        if (in.available() != 0) {
            throw new GeneralSecurityException("Bytes extra inesperados no ficheiro de contactos.");
        }
    }

    private void guardar() throws IOException, GeneralSecurityException {
        if (ficheiro.getParent() != null) {
            Files.createDirectories(ficheiro.getParent());
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buffer);
        out.write(CABECALHO_FICHEIRO);
        out.writeInt(impressoesDigitais.size());
        for (Map.Entry<String, byte[]> entry : impressoesDigitais.entrySet()) {
            out.writeUTF(entry.getKey());
            Bytes.escrever(out, entry.getValue());
        }

        byte[] payload = buffer.toByteArray();
        byte[] hmac = calcularHmac(payload);
        buffer.write(hmac);

        Path temporario = ficheiro.resolveSibling(ficheiro.getFileName() + ".tmp");
        Files.write(temporario, buffer.toByteArray());
        Files.move(temporario, ficheiro, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private byte[] calcularHmac(byte[] dados) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(chaveHmac, "HmacSHA256"));
        return mac.doFinal(dados);
    }

    public synchronized void destruir() {
        Arrays.fill(chaveHmac, (byte) 0);
    }
}