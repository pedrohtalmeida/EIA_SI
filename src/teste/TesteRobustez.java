package teste;

import client.Levantar;
import common.Chaves;
import common.Registo;
import common.Tipos;
import common.Trama;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import relay.RelayMain;

/*
 A4 - Robustez do relay (disponibilidade), com um relay verdadeiro e valores pequenos:
   - no maximo 3 ligacoes ao mesmo tempo;
   - o resto de uma trama tem de chegar em 500 ms;
   - uma ligacao por autenticar e fechada ao fim de 1 s parada.
 */
public class TesteRobustez {

    private static int falhas = 0;

    public static void main(String[] args) throws Exception {
        // Tem de ser antes de a classe RelayMain ser usada (os valores sao lidos uma vez).
        System.setProperty("relay.maxLigacoes", "3");
        System.setProperty("relay.tempoTramaMs", "500");
        System.setProperty("relay.tempoAutenticacaoMs", "1000");

        ServerSocket servidor = new ServerSocket(0); // porto livre
        Thread relay = new Thread(() -> {
            try {
                RelayMain.servir(servidor);
            } catch (IOException e) {
                // fecha no fim do teste
            }
        });
        relay.setDaemon(true);
        relay.start();
        int porto = servidor.getLocalPort();

        // 1. Slowloris: envia so o 1.o byte de uma trama e para.
        //    Enquanto isso, outro cliente tem de ser atendido normalmente.
        try (Socket lento = new Socket("localhost", porto)) {
            lento.getOutputStream().write(Tipos.PROCURAR); // so o tipo; faltam o tamanho e o corpo
            lento.getOutputStream().flush();

            try (Socket normal = new Socket("localhost", porto)) {
                Trama r = pedido(normal, Tipos.PROCURAR, "ninguem".getBytes(StandardCharsets.UTF_8));
                verificar("Com uma trama a meio noutra ligacao, os outros sao atendidos", r.tipo == Tipos.ERRO);
            }
            verificar("Trama incompleta: o relay fecha a ligacao (tempo limite da trama)", fechadaPeloRelay(lento, 3000));
        }

        // 2. Ligacao parada sem se autenticar: fechada pelo relay
        try (Socket parada = new Socket("localhost", porto)) {
            verificar("Ligacao parada sem autenticacao: fechada ao fim do tempo limite", fechadaPeloRelay(parada, 4000));
        }

        // 3. Tamanho gigante no cabecalho: fechada sem reservar memoria
        try (Socket gigante = new Socket("localhost", porto)) {
            DataOutputStream out = new DataOutputStream(gigante.getOutputStream());
            out.writeByte(Tipos.PROCURAR);
            out.writeInt(2_000_000_000); // ~2 GB anunciados
            out.flush();
            verificar("Trama com 2 GB anunciados: ligacao fechada", fechadaPeloRelay(gigante, 3000));
        }

        // 4. Cliente autenticado pode ficar parado (esta a espera de mensagens)
        KeyPair ed = Chaves.gerarParAssinatura(), x = Chaves.gerarParAcordo();
        try (Socket ana = new Socket("localhost", porto)) {
            pedido(ana, Tipos.REGISTO, Registo.criar("ana", ed, x));
            Levantar.executar((t, c) -> pedido(ana, t, c), "ana", ed.getPrivate());
            Thread.sleep(2000); // mais do que o tempo limite de quem nao esta autenticado
            Trama r = pedido(ana, Tipos.PROCURAR, "ana".getBytes(StandardCharsets.UTF_8));
            verificar("Cliente autenticado parado 2 s continua ligado", r.tipo == Tipos.PROCURAR_RESP);
        }
        Thread.sleep(300); // o relay liberta os lugares das ligacoes fechadas

        // 5. Limite de ligacoes simultaneas (3)
        Socket a = new Socket("localhost", porto);
        Socket b = new Socket("localhost", porto);
        Socket c = new Socket("localhost", porto);
        Thread.sleep(200);
        try (Socket quarta = new Socket("localhost", porto)) {
            verificar("4.a ligacao com o limite em 3: recusada", fechadaPeloRelay(quarta, 500));
        }
        a.close();
        Thread.sleep(300);
        try (Socket nova = new Socket("localhost", porto)) {
            Trama r = pedido(nova, Tipos.PROCURAR, "ana".getBytes(StandardCharsets.UTF_8));
            verificar("Depois de uma fechar, ja ha lugar para uma nova", r.tipo == Tipos.PROCURAR_RESP);
        }
        b.close();
        c.close();

        servidor.close();
        System.out.println(falhas == 0 ? "\nTodos os testes passaram." : "\n" + falhas + " teste(s) falharam.");
        System.exit(falhas == 0 ? 0 : 1);
    }

    static Trama pedido(Socket s, byte tipo, byte[] corpo) throws IOException {
        Trama.escrever(new DataOutputStream(s.getOutputStream()), tipo, corpo);
        return Trama.ler(new DataInputStream(s.getInputStream()));
    }

    // true se o relay fechar a ligacao dentro de 'esperaMs'.
    static boolean fechadaPeloRelay(Socket s, int esperaMs) {
        try {
            s.setSoTimeout(esperaMs);
            return s.getInputStream().read() == -1; // -1 = o relay fechou
        } catch (java.net.SocketTimeoutException e) {
            return false;                           // continuou aberta
        } catch (IOException e) {
            return true;                            // ligacao cortada pelo relay
        }
    }

    static void verificar(String descricao, boolean ok) {
        if (!ok) {
            falhas++;
        }
        System.out.println((ok ? "PASSOU  " : "FALHOU  ") + descricao);
    }
}