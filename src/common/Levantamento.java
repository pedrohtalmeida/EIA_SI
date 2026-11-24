package common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;

/*
 Modulo C: formato partilhado pelo cliente e pelo relay no levantamento
 por desafio-resposta.
 
 O que o cliente assina:
   writeUTF(CONTEXTO) | writeUTF(nome) | [len][nonce]
 
 O texto de contexto impede que uma assinatura feita para outra parte do
 protocolo (por exemplo, o registo ou uma mensagem) seja aproveitada como
 resposta a um desafio. O nome liga a assinatura ao utilizador que levanta.
 */
public final class Levantamento {

    public static final String CONTEXTO = "MensageiroSeguro v1 levantar";
    public static final int TAM_NONCE = 32;

    private Levantamento() {}

    // Bytes exatos que o cliente assina e que o relay verifica.
    public static byte[] dadosAssinados(String nome, byte[] nonce) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream d = new DataOutputStream(buffer);
            d.writeUTF(CONTEXTO);
            d.writeUTF(nome);
            Bytes.escrever(d, nonce);
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e); // nao acontece a escrever para memoria
        }
    }

    // Corpo da trama RESPOSTA: [len][nonce] [len][assinatura]
    public static byte[] resposta(byte[] nonce, byte[] assinatura) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream d = new DataOutputStream(buffer);
            Bytes.escrever(d, nonce);
            Bytes.escrever(d, assinatura);
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // Le o corpo da trama RESPOSTA. Devolve {nonce, assinatura}.
    public static byte[][] lerResposta(byte[] corpo) throws IOException {
        DataInputStream d = new DataInputStream(new ByteArrayInputStream(corpo));
        byte[] nonce = Bytes.ler(d, TAM_NONCE);
        byte[] assinatura = Bytes.ler(d, Registo.MAX_ASSINATURA);
        if (d.available() != 0) {
            throw new IOException("Bytes a mais na resposta ao desafio");
        }
        return new byte[][] {nonce, assinatura};
    }
}