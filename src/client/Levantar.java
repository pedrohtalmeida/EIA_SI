package client;

import common.Chaves;
import common.Levantamento;
import common.Tipos;
import common.Trama;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

/*
 * A3 - Comando levantar (lado do cliente do modulo C).
 *
 *   cliente -> relay  : LEVANTAR(nome)
 *   relay   -> cliente: DESAFIO(nonce)
 *   cliente -> relay  : RESPOSTA(nonce, Ed25519(dadosAssinados(nome, nonce)))
 *   relay   -> cliente: ENTREGA x n  (as mensagens pendentes, por ordem)
 *                       LEVANTAR_OK(n)
 *
 * Depois disto a ligacao fica autenticada: o relay passa a entregar as
 * mensagens novas em direto e aceita pedidos ENVIAR desta ligacao.
 */
public final class Levantar {

    // Envia um pedido ao relay e devolve a resposta (no ClientMain: o metodo pedido).
    public interface Canal {
        Trama pedido(byte tipo, byte[] corpo) throws IOException, InterruptedException;
    }

    private Levantar() {}

    // Devolve o numero de mensagens pendentes que o relay entregou.
    public static int executar(Canal canal, String nome, PrivateKey chaveAssinatura) throws Exception {
        Trama desafio = canal.pedido(Tipos.LEVANTAR, nome.getBytes(StandardCharsets.UTF_8));
        if (desafio.tipo != Tipos.DESAFIO) {
            throw new IOException(texto(desafio));
        }
        byte[] nonce = desafio.corpo;
        if (nonce.length != Levantamento.TAM_NONCE) {
            throw new IOException("Desafio com tamanho invalido");
        }

        byte[] assinatura = Chaves.assinar(chaveAssinatura, Levantamento.dadosAssinados(nome, nonce));
        Trama r = canal.pedido(Tipos.RESPOSTA, Levantamento.resposta(nonce, assinatura));
        if (r.tipo != Tipos.LEVANTAR_OK || r.corpo.length != 4) {
            throw new IOException(texto(r));
        }
        return ByteBuffer.wrap(r.corpo).getInt();
    }

    private static String texto(Trama t) {
        return new String(t.corpo, StandardCharsets.UTF_8);
    }
}