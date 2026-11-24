package teste;

import client.Levantar;
import common.Bytes;
import common.Chaves;
import common.Mensagem;
import common.Registo;
import common.Tipos;
import common.Trama;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import relay.RelayMain;

/*
 * A1 ponta a ponta: relay verdadeiro num porto livre e clientes por sockets.
 * Verifica que, com o destinatario desligado, o relay guarda a mensagem
 * em vez de responder "Destinatario desligado".
 */
public class TesteArmazenamento {

    private static int falhas = 0;

    // Cliente minimo e sincrono: envia um pedido e devolve a resposta.
    static final class Cliente implements AutoCloseable {
        final Socket s;
        final DataInputStream in;
        final DataOutputStream out;

        Cliente(int porto) throws IOException {
            s = new Socket("localhost", porto);
            in = new DataInputStream(s.getInputStream());
            out = new DataOutputStream(s.getOutputStream());
        }

        Trama pedido(byte tipo, byte[] corpo) throws IOException {
            Trama.escrever(out, tipo, corpo);
            return Trama.ler(in);
        }

        public void close() throws IOException {
            s.close();
        }
    }

    public static void main(String[] args) throws Exception {
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

        KeyPair anaEd = Chaves.gerarParAssinatura(), anaX = Chaves.gerarParAcordo();
        KeyPair brunoEd = Chaves.gerarParAssinatura(), brunoX = Chaves.gerarParAcordo();

        // O bruno regista-se e fica ligado
        Cliente bruno = new Cliente(porto);
        bruno.pedido(Tipos.REGISTO, Registo.criar("bruno", brunoEd, brunoX));
        Levantar.executar(bruno::pedido, "bruno", brunoEd.getPrivate());

        try (Cliente ana = new Cliente(porto)) {
            ana.pedido(Tipos.REGISTO, Registo.criar("ana", anaEd, anaX));
            Levantar.executar(ana::pedido, "ana", anaEd.getPrivate());
            Registo regBruno = Registo.ler(ana.pedido(Tipos.PROCURAR, "bruno".getBytes(StandardCharsets.UTF_8)).corpo);

            // 1. Bruno ligado: entregue em direto
            Trama r1 = ana.pedido(Tipos.ENVIAR, corpoEnviar("bruno", envelope(anaEd, anaX, regBruno, "em direto")));
            verificar("Bruno ligado: ENVIAR_OK \"entregue\"", ok(r1, "entregue"));
            Trama recebida = Trama.ler(bruno.in);
            verificar("...e o bruno recebeu a ENTREGA", recebida.tipo == Tipos.ENTREGA);

            // 2. O bruno desliga-se
            bruno.close();
            Thread.sleep(200); // o relay processa o fecho da ligacao

            // 3. Bruno desligado: a mensagem fica guardada (antes: "Destinatario desligado")
            Trama r2 = ana.pedido(Tipos.ENVIAR, corpoEnviar("bruno", envelope(anaEd, anaX, regBruno, "primeira")));
            verificar("Bruno desligado: ENVIAR_OK \"guardada\"", ok(r2, "guardada"));
            Trama r3 = ana.pedido(Tipos.ENVIAR, corpoEnviar("bruno", envelope(anaEd, anaX, regBruno, "segunda")));
            verificar("Segunda mensagem tambem guardada", ok(r3, "guardada"));

            // 4. Para um nome que nao existe nao se guarda nada
            Trama r4 = ana.pedido(Tipos.ENVIAR, corpoEnviar("zeca", new byte[] {1, 2, 3}));
            verificar("Destinatario desconhecido: ERRO (nada guardado)", r4.tipo == Tipos.ERRO);
        }

        servidor.close();
        System.out.println(falhas == 0 ? "\nTodos os testes passaram." : "\n" + falhas + " teste(s) falharam.");
        System.exit(falhas == 0 ? 0 : 1);
    }

    static byte[] envelope(KeyPair ed, KeyPair x, Registo destino, String texto) throws Exception {
        return Mensagem.selar("ana", ed, x.getPrivate(), destino, texto);
    }

    static byte[] corpoEnviar(String destino, byte[] envelope) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(buffer);
        d.writeUTF(destino);
        Bytes.escrever(d, envelope);
        return buffer.toByteArray();
    }

    static boolean ok(Trama t, String esperado) {
        return t.tipo == Tipos.ENVIAR_OK && new String(t.corpo, StandardCharsets.UTF_8).equals(esperado);
    }

    static void verificar(String descricao, boolean ok) {
        if (!ok) {
            falhas++;
        }
        System.out.println((ok ? "PASSOU  " : "FALHOU  ") + descricao);
    }
}
