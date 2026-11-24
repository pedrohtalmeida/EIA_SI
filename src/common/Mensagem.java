package common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;

/*
 * Envelope de uma mensagem (cifrado ponta a ponta com Ratchet simétrico - Módulo B).
 *
 * Formato:
 *   cabecalho = writeUTF(remetente) | writeUTF(destinatario) | writeLong(instante)
 *             | writeLong(idSessao) | writeLong(contador)
 *   envelope  = cabecalho | [len][iv] | [len][cifrado] | [len][assinatura]
 *
 *   chave      = MK_contador derivada da CadeiaChaves (ECDH X25519 + HKDF-SHA256)
 *   cifrado    = AES-256-GCM(chave, iv, texto, AAD = cabecalho)
 *   assinatura = Ed25519(remetente, tudo o que vem antes dela)
 */
public final class Mensagem {

    private static final int MAX_CIFRADO = Trama.MAX_CORPO;

    public final String remetente;
    public final String destinatario;
    public final long instante;
    public final long idSessao;
    public final long contador;

    private final byte[] cabecalho;
    private final byte[] iv;
    private final byte[] cifrado;
    private final byte[] assinados;
    private final byte[] assinatura;

    private Mensagem(String remetente, String destinatario, long instante, long idSessao, long contador,
                     byte[] cabecalho, byte[] iv, byte[] cifrado, byte[] assinados, byte[] assinatura) {
        this.remetente = remetente;
        this.destinatario = destinatario;
        this.instante = instante;
        this.idSessao = idSessao;
        this.contador = contador;
        this.cabecalho = cabecalho;
        this.iv = iv;
        this.cifrado = cifrado;
        this.assinados = assinados;
        this.assinatura = assinatura;
    }

    // Remetente: avança a cadeia de envio, cifra e assina. Devolve os bytes do envelope.
    public static byte[] selar(String remetente, KeyPair minhaAssinatura, CadeiaChaves cadeiaEnvio,
                               Registo destino, String texto) throws IOException, GeneralSecurityException {
        CadeiaChaves.PassoEnvio passo = cadeiaEnvio.avancarParaEnvio();
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream d = new DataOutputStream(buffer);
            d.writeUTF(remetente);
            d.writeUTF(destino.nome);
            d.writeLong(System.currentTimeMillis());
            d.writeLong(passo.idSessao);
            d.writeLong(passo.contador);
            byte[] cabecalho = buffer.toByteArray();

            byte[] iv = Cifra.novoIv();
            byte[] cifrado = Cifra.cifrar(passo.chaveMensagem, iv, texto.getBytes(StandardCharsets.UTF_8), cabecalho);

            Bytes.escrever(d, iv);
            Bytes.escrever(d, cifrado);
            byte[] assinados = buffer.toByteArray();
            Bytes.escrever(d, Chaves.assinar(minhaAssinatura.getPrivate(), assinados));
            return buffer.toByteArray();
        } finally {
            Arrays.fill(passo.chaveMensagem, (byte) 0);
        }
    }

    // Sobrecarga de compatibilidade para testes que passam diretamente a PrivateKey X25519.
    public static byte[] selar(String remetente, KeyPair minhaAssinatura, PrivateKey meuAcordo,
                               Registo destino, String texto) throws IOException, GeneralSecurityException {
        CadeiaChaves cadeia = CadeiaChaves.criarParaEnvio(meuAcordo, destino.chaveAcordo, remetente, destino.nome);
        try {
            return selar(remetente, minhaAssinatura, cadeia, destino, texto);
        } finally {
            cadeia.destruir();
        }
    }

    // Destinatário, passo 1: lê o envelope (ainda sem verificar nada), para saber quem o enviou e qual a sessão.
    public static Mensagem ler(byte[] envelope) throws IOException {
        DataInputStream d = new DataInputStream(new ByteArrayInputStream(envelope));
        String remetente = d.readUTF();
        String destinatario = d.readUTF();
        long instante = d.readLong();
        long idSessao = d.readLong();
        long contador = d.readLong();
        byte[] cabecalho = Arrays.copyOf(envelope, envelope.length - d.available());

        byte[] iv = Bytes.ler(d, Cifra.TAM_IV);
        if (iv.length != Cifra.TAM_IV) {
            throw new IOException("IV com tamanho errado");
        }
        byte[] cifrado = Bytes.ler(d, MAX_CIFRADO);
        byte[] assinados = Arrays.copyOf(envelope, envelope.length - d.available());
        byte[] assinatura = Bytes.ler(d, Registo.MAX_ASSINATURA);
        if (d.available() != 0) {
            throw new IOException("Bytes a mais no envelope");
        }
        return new Mensagem(remetente, destinatario, instante, idSessao, contador,
                cabecalho, iv, cifrado, assinados, assinatura);
    }

    // Destinatário, passo 2: verifica a assinatura, obtém a chave da cadeia (tratando fora de ordem/repetição) e decifra.
    public String abrir(String meuNome, CadeiaChaves cadeiaRececao, Registo registoRemetente)
            throws GeneralSecurityException {
        if (!destinatario.equals(meuNome)) {
            throw new GeneralSecurityException("Mensagem nao e para mim");
        }
        if (!registoRemetente.nome.equals(remetente)) {
            throw new GeneralSecurityException("Registo nao corresponde ao remetente");
        }
        if (cadeiaRececao.getIdSessao() != idSessao) {
            throw new GeneralSecurityException("ID de sessao da cadeia nao corresponde a mensagem");
        }
        if (!Chaves.verificar(registoRemetente.chaveAssinatura, assinados, assinatura)) {
            throw new GeneralSecurityException("Assinatura da mensagem invalida");
        }

        byte[] chave = cadeiaRececao.obterChaveParaRececao(contador);
        try {
            byte[] claro = Cifra.decifrar(chave, iv, cifrado, cabecalho);
            return new String(claro, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(chave, (byte) 0);
        }
    }

    // Sobrecarga de compatibilidade para testes que passam diretamente a PrivateKey X25519.
    public String abrir(String meuNome, PrivateKey meuAcordo, Registo registoRemetente)
            throws GeneralSecurityException {
        CadeiaChaves cadeia = CadeiaChaves.criarComSessao(
                idSessao, meuAcordo, registoRemetente.chaveAcordo, remetente, meuNome);
        try {
            return abrir(meuNome, cadeia, registoRemetente);
        } finally {
            cadeia.destruir();
        }
    }
}