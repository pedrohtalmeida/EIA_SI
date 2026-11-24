package relay;

import common.Tipos;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/*
 A1 - Armazenamento diferido.
 *
 Cada utilizador tem uma "caixa" com:
   - a ligacao ativa (null se estiver desligado);
   - a fila das mensagens pendentes, pela ordem em que chegaram.
 
 O relay so guarda os envelopes JA CIFRADOS pelo remetente: nunca tem acesso
 ao conteudo, nem em transito nem enquanto as mensagens estao guardadas.
 
 Decisao: as pendentes ficam so em memoria. Se o relay for reiniciado,
 perdem-se (limitacao a documentar no relatorio).
 
 Concorrencia: "esta ligado? entao entrega, senao guarda" e feito com o lock
 da caixa do destinatario, para nao haver uma mensagem guardada no mesmo
 instante em que o destinatario se liga (ou entregue a uma ligacao que
 acabou de fechar).
 
 A entrega das pendentes ao destinatario legitimo e feita no levantamento
 por desafio-resposta (modulo C, A2/A3), que usa entregarPendentes().
 */
public final class Pendentes {

    // Limites para um remetente malicioso nao esgotar a memoria do relay.
    public static final int MAX_MENSAGENS_POR_UTILIZADOR = 100;
    public static final long MAX_BYTES_POR_UTILIZADOR = 1L << 20;  // 1 MiB
    public static final long MAX_BYTES_TOTAL = 64L << 20;          // 64 MiB no relay inteiro

    public enum Resultado { ENTREGUE, GUARDADA, CAIXA_CHEIA }

    private static final class Caixa {
        final ArrayDeque<byte[]> fila = new ArrayDeque<>();
        long bytes = 0;
        Ligacao ligacao = null;
    }

    private final ConcurrentHashMap<String, Caixa> caixas = new ConcurrentHashMap<>();
    private final AtomicLong bytesTotal = new AtomicLong();

    private Caixa caixa(String nome) {
        return caixas.computeIfAbsent(nome, n -> new Caixa());
    }

    // Se o destinatario estiver ligado, entrega ja; senao guarda (se couber nos limites).
    public Resultado entregarOuGuardar(String destino, byte[] envelope) {
        Caixa c = caixa(destino);
        synchronized (c) {
            if (c.ligacao != null) {
                try {
                    c.ligacao.enviar(Tipos.ENTREGA, envelope);
                    return Resultado.ENTREGUE;
                } catch (IOException e) {
                    c.ligacao = null; // a ligacao caiu: a mensagem fica guardada
                }
            }
            if (c.fila.size() >= MAX_MENSAGENS_POR_UTILIZADOR
                    || c.bytes + envelope.length > MAX_BYTES_POR_UTILIZADOR) {
                return Resultado.CAIXA_CHEIA;
            }
            if (bytesTotal.addAndGet(envelope.length) > MAX_BYTES_TOTAL) {
                bytesTotal.addAndGet(-envelope.length);
                return Resultado.CAIXA_CHEIA;
            }
            c.fila.addLast(envelope);
            c.bytes += envelope.length;
            return Resultado.GUARDADA;
        }
    }

    // Marca a ligacao como a ativa deste utilizador: as mensagens novas passam
    // a ser entregues em direto. (Se ja havia outra, esta substitui-a.)
    public void ligar(String nome, Ligacao lig) {
        Caixa c = caixa(nome);
        synchronized (c) {
            c.ligacao = lig;
        }
    }

    // Quando a ligacao fecha. So desliga se ainda for esta a ligacao ativa
    // (se o utilizador ja se ligou noutra, essa continua a ativa).
    public void desligar(String nome, Ligacao lig) {
        Caixa c = caixas.get(nome);
        if (c != null) {
            synchronized (c) {
                if (c.ligacao == lig) {
                    c.ligacao = null;
                }
            }
        }
    }

    // Entrega as pendentes de 'nome' em 'lig', pela ordem de chegada, e apaga-as.
    // Cada mensagem so sai da fila depois de ter sido escrita com sucesso.
    // ATENCAO: so deve ser chamado depois de o relay confirmar que quem pede
    // e o destinatario legitimo (modulo C). Devolve quantas foram entregues.
    public int entregarPendentes(String nome, Ligacao lig) throws IOException {
        Caixa c = caixa(nome);
        synchronized (c) {
            int entregues = 0;
            while (!c.fila.isEmpty()) {
                byte[] envelope = c.fila.peekFirst();
                lig.enviar(Tipos.ENTREGA, envelope);
                c.fila.removeFirst();
                c.bytes -= envelope.length;
                bytesTotal.addAndGet(-envelope.length);
                entregues++;
            }
            return entregues;
        }
    }

    // Entrega as pendentes e marca a ligacao como ativa, tudo com o mesmo lock:
    // assim nenhuma mensagem nova passa a frente das antigas nem fica esquecida na fila.
    public int ligarEEntregar(String nome, Ligacao lig) throws IOException {
        Caixa c = caixa(nome);
        synchronized (c) {
            int entregues = entregarPendentes(nome, lig);
            c.ligacao = lig;
            return entregues;
        }
    }

    // Numero de mensagens guardadas para um utilizador.
    public int quantas(String nome) {
        Caixa c = caixas.get(nome);
        if (c == null) {
            return 0;
        }
        synchronized (c) {
            return c.fila.size();
        }
    }
}