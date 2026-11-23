package teste;

import common.Tipos;
import common.Trama;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import relay.Ligacao;
import relay.Pendentes;

/* A1: testa o armazenamento diferido do relay (classe Pendentes), sem rede. */
public class TestePendentes {

    private static int falhas = 0;

    public static void main(String[] args) throws Exception {
        Pendentes p = new Pendentes();

        // 1. Destinatario desligado: as mensagens ficam guardadas
        verificar("Mensagem 1 guardada com o destinatario desligado",
                p.entregarOuGuardar("bruno", new byte[] {1}) == Pendentes.Resultado.GUARDADA);
        verificar("Mensagem 2 guardada com o destinatario desligado",
                p.entregarOuGuardar("bruno", new byte[] {2}) == Pendentes.Resultado.GUARDADA);
        verificar("O relay tem 2 pendentes para o bruno", p.quantas("bruno") == 2);

        // 2. Destinatario ligado: entregue em direto, nada fica guardado
        ByteArrayOutputStream saida = new ByteArrayOutputStream();
        Ligacao lig = new Ligacao(new DataOutputStream(saida));
        p.ligar("bruno", lig);
        verificar("Destinatario ligado: entregue em direto",
                p.entregarOuGuardar("bruno", new byte[] {3}) == Pendentes.Resultado.ENTREGUE);
        Trama direta = Trama.ler(new DataInputStream(new ByteArrayInputStream(saida.toByteArray())));
        verificar("...chegou como ENTREGA com o mesmo conteudo",
                direta.tipo == Tipos.ENTREGA && direta.corpo[0] == 3);
        verificar("...e as 2 antigas continuam guardadas", p.quantas("bruno") == 2);

        // 3. Entregar as pendentes: pela ordem de chegada, e a fila fica vazia
        ByteArrayOutputStream saida2 = new ByteArrayOutputStream();
        int entregues = p.entregarPendentes("bruno", new Ligacao(new DataOutputStream(saida2)));
        DataInputStream lido = new DataInputStream(new ByteArrayInputStream(saida2.toByteArray()));
        Trama t1 = Trama.ler(lido), t2 = Trama.ler(lido);
        verificar("Entregou as 2 pendentes", entregues == 2);
        verificar("...pela ordem de chegada", t1.corpo[0] == 1 && t2.corpo[0] == 2);
        verificar("...e a fila ficou vazia", p.quantas("bruno") == 0);

        // 4. Depois de se desligar, volta a guardar
        p.desligar("bruno", lig);
        verificar("Depois de desligar, volta a guardar",
                p.entregarOuGuardar("bruno", new byte[] {4}) == Pendentes.Resultado.GUARDADA);

        // 5. Desligar uma ligacao antiga nao desliga a nova
        Ligacao antiga = new Ligacao(new DataOutputStream(new ByteArrayOutputStream()));
        Ligacao nova = new Ligacao(new DataOutputStream(new ByteArrayOutputStream()));
        p.ligar("eva", antiga);
        p.ligar("eva", nova);      // a eva liga-se noutra janela
        p.desligar("eva", antiga); // a janela antiga fecha
        verificar("Fechar a ligacao antiga nao desliga a nova",
                p.entregarOuGuardar("eva", new byte[] {5}) == Pendentes.Resultado.ENTREGUE);

        // 6. Ligacao que caiu: a mensagem fica guardada em vez de se perder
        Ligacao partida = new Ligacao(new DataOutputStream(new java.io.OutputStream() {
            public void write(int b) throws java.io.IOException {
                throw new java.io.IOException("ligacao caiu");
            }
        }));
        p.ligar("filipe", partida);
        verificar("Ligacao caida: a mensagem fica guardada",
                p.entregarOuGuardar("filipe", new byte[] {6}) == Pendentes.Resultado.GUARDADA
                        && p.quantas("filipe") == 1);

        // 7. Limite de numero de mensagens por utilizador
        for (int i = 0; i < Pendentes.MAX_MENSAGENS_POR_UTILIZADOR; i++) {
            p.entregarOuGuardar("carla", new byte[] {0});
        }
        verificar("Mensagem " + (Pendentes.MAX_MENSAGENS_POR_UTILIZADOR + 1) + " recusada: caixa cheia",
                p.entregarOuGuardar("carla", new byte[] {0}) == Pendentes.Resultado.CAIXA_CHEIA);

        // 8. Limite de bytes por utilizador
        byte[] grande = new byte[60 * 1024];
        int guardadas = 0;
        while (p.entregarOuGuardar("dina", grande) == Pendentes.Resultado.GUARDADA) {
            guardadas++;
        }
        verificar("Limite de 1 MiB por utilizador (guardou " + guardadas + " mensagens de 60 KiB)",
                guardadas > 0 && guardadas * (long) grande.length <= Pendentes.MAX_BYTES_POR_UTILIZADOR);

        System.out.println(falhas == 0 ? "\nTodos os testes passaram." : "\n" + falhas + " teste(s) falharam.");
        System.exit(falhas == 0 ? 0 : 1);
    }

    static void verificar(String descricao, boolean ok) {
        if (!ok) {
            falhas++;
        }
        System.out.println((ok ? "PASSOU  " : "FALHOU  ") + descricao);
    }
}
