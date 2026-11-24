package client;

import common.Bytes;
import common.CadeiaChaves;
import common.Cifra;
import common.Hkdf;
import common.Registo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Cadeias de rececao do Ratchet (modulo B), uma por (remetente, sessao), guardadas em
 * ficheiro cifrado para sobreviverem a reinicios do cliente.
 *
 * Corrige dois problemas:
 *  1. Reiniciar o cliente perdia o estado: a conversa partia-se (limite de chaves saltadas)
 *     e as mensagens antigas voltavam a ser aceites.
 *  2. Guardar so uma cadeia por remetente: ao chegar outra sessao, a anterior era destruida
 *     e uma mensagem antiga reenviada pelo relay voltava a ser aceite.
 *
 * Ficheiro dados/<nome>.cadeias:  [iv] [cifrado]
 *   cifrado = AES-256-GCM(chave, iv, estado, AAD = "cadeias|" + nome)
 *   chave   = HKDF(chave privada Ed25519 da identidade, "cadeias|" + nome)
 */
public final class GestorCadeias {

    // Limite de sessoes guardadas (memoria e disco limitados). Ao exceder, esquece a menos usada.
    public static final int MAX_SESSOES = 100;

    private static final byte[] CABECALHO = "EIASICADEIAS1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SALT = "EIA-SI-CADEIAS-V1".getBytes(StandardCharsets.UTF_8);
    private static final int MAX_FICHEIRO = 4 * 1024 * 1024;

    private final Path ficheiro;
    private final byte[] chaveFicheiro;
    private final byte[] aad;

    // Ordem de acesso: a "mais antiga" e a menos usada recentemente.
    private final LinkedHashMap<String, CadeiaChaves> cadeias =
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, CadeiaChaves> eldest) {
                    if (size() > MAX_SESSOES) {
                        eldest.getValue().destruir();
                        return true;
                    }
                    return false;
                }
            };

    private GestorCadeias(Path ficheiro, byte[] chaveFicheiro, String nome) {
        this.ficheiro = ficheiro;
        this.chaveFicheiro = chaveFicheiro;
        this.aad = ("cadeias|" + nome).getBytes(StandardCharsets.UTF_8);
    }

    // Carrega o estado do ficheiro (se existir). Se o ficheiro foi alterado, falha.
    public static GestorCadeias carregar(Path ficheiro, Identidade identidade)
            throws IOException, GeneralSecurityException {
        byte[] ikm = identidade.getAssinaturaEd25519().getPrivate().getEncoded();
        byte[] chave;
        try {
            chave = Hkdf.derivar(ikm, SALT, "cadeias|" + identidade.getNome(), 32);
        } finally {
            Arrays.fill(ikm, (byte) 0);
        }
        GestorCadeias g = new GestorCadeias(ficheiro, chave, identidade.getNome());
        if (Files.exists(ficheiro)) {
            g.ler();
        }
        return g;
    }

    // Devolve a cadeia desta (remetente, sessao); se for uma sessao nova, cria-a.
    public synchronized CadeiaChaves obter(Registo remetente, long idSessao,
                                           PrivateKey meuAcordo, String meuNome)
            throws GeneralSecurityException {
        String chave = remetente.nome + "|" + idSessao;
        CadeiaChaves c = cadeias.get(chave);
        if (c == null) {
            c = CadeiaChaves.criarComSessao(idSessao, meuAcordo, remetente.chaveAcordo,
                    remetente.nome, meuNome);
            cadeias.put(chave, c);
        }
        return c;
    }

    public synchronized int tamanho() {
        return cadeias.size();
    }

    // Grava o estado atual (cifrado). Chamar depois de cada mensagem recebida.
    public synchronized void guardar() throws IOException, GeneralSecurityException {
        ByteArrayOutputStream claro = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(claro);
        d.write(CABECALHO);
        d.writeInt(cadeias.size());
        for (Map.Entry<String, CadeiaChaves> e : cadeias.entrySet()) {
            String remetente = e.getKey().substring(0, e.getKey().lastIndexOf('|'));
            d.writeUTF(remetente);
            Bytes.escrever(d, e.getValue().serializar());
        }

        byte[] iv = Cifra.novoIv();
        byte[] cifrado = Cifra.cifrar(chaveFicheiro, iv, claro.toByteArray(), aad);

        ByteArrayOutputStream saida = new ByteArrayOutputStream();
        DataOutputStream o = new DataOutputStream(saida);
        Bytes.escrever(o, iv);
        Bytes.escrever(o, cifrado);

        if (ficheiro.getParent() != null) {
            Files.createDirectories(ficheiro.getParent());
        }
        Path temporario = ficheiro.resolveSibling(ficheiro.getFileName() + ".tmp");
        Files.write(temporario, saida.toByteArray());
        try {
            Files.setPosixFilePermissions(temporario, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException e) {
            // sistema sem permissoes POSIX
        }
        Files.move(temporario, ficheiro, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private void ler() throws IOException, GeneralSecurityException {
        byte[] total = Files.readAllBytes(ficheiro);
        if (total.length > MAX_FICHEIRO) {
            throw new GeneralSecurityException("Ficheiro de cadeias demasiado grande.");
        }
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(total));
        byte[] iv = Bytes.ler(in, Cifra.TAM_IV);
        byte[] cifrado = Bytes.ler(in, MAX_FICHEIRO);

        byte[] claro;
        try {
            claro = Cifra.decifrar(chaveFicheiro, iv, cifrado, aad);
        } catch (GeneralSecurityException e) {
            throw new GeneralSecurityException(
                    "ALERTA DE INTEGRIDADE: o ficheiro de cadeias '" + ficheiro + "' foi adulterado "
                    + "ou nao pertence a esta identidade.");
        }

        DataInputStream d = new DataInputStream(new ByteArrayInputStream(claro));
        byte[] cabecalho = new byte[CABECALHO.length];
        d.readFully(cabecalho);
        if (!Arrays.equals(cabecalho, CABECALHO)) {
            throw new GeneralSecurityException("Formato invalido do ficheiro de cadeias.");
        }
        int n = d.readInt();
        if (n < 0 || n > MAX_SESSOES) {
            throw new GeneralSecurityException("Numero de cadeias invalido.");
        }
        cadeias.clear();
        for (int i = 0; i < n; i++) {
            String remetente = d.readUTF();
            CadeiaChaves c = CadeiaChaves.desserializar(Bytes.ler(d, 64 * 1024));
            cadeias.put(remetente + "|" + c.getIdSessao(), c);
        }
        if (d.available() != 0) {
            throw new GeneralSecurityException("Bytes a mais no ficheiro de cadeias.");
        }
    }
}
