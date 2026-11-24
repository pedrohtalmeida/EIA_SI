package teste;

import client.Levantar;
import common.Bytes;
import common.Chaves;
import common.Levantamento;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import relay.RelayMain;

/*
 * Modulo C (A2 + A3) ponta a ponta: relay verdadeiro num porto livre e clientes por sockets.
 *
 * Os "envelopes" sao bytes quaisquer: o relay nao os le, so os guarda e entrega.
 * Assim o teste nao depende da forma como as mensagens sao cifradas (modulo B).
 */
public class TesteLevantamento {

    private static int falhas = 0;

    // Cliente minimo e sincrono: guarda as ENTREGA que chegam e devolve a resposta ao pedido.
    static final class Cliente implements AutoCloseable {
        final Socket s;
        final DataInputStream in;
        final DataOutputStream out;
        final List<byte[]> recebidas = new ArrayList<>();

        Cliente(int porto) throws IOException {
            s = new Socket("localhost", porto);
            in = new DataInputStream(s.getInputStream());
            out = new DataOutputStream(s.getOutputStream());
        }

        Trama pedido(byte tipo, byte[] corpo) throws IOException {
            Trama.escrever(out, tipo, corpo);
            while (true) {
                Trama t = Trama.ler(in);
                if (t.tipo == Tipos.ENTREGA) {
                    recebidas.add(t.corpo);
                } else {
                    return t;
                }
            }
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
        KeyPair malloryEd = Chaves.gerarParAssinatura();
        byte[] respostaGravada;

        // 1. O bruno regista-se, autentica-se e desliga-se.
        //    Um atacante na rede grava uma resposta valida do bruno.
        try (Cliente bruno = new Cliente(porto)) {
            bruno.pedido(Tipos.REGISTO, Registo.criar("bruno", brunoEd, brunoX));
            int n = Levantar.executar(bruno::pedido, "bruno", brunoEd.getPrivate());
            verificar("Bruno autentica-se (0 pendentes)", n == 0);

            Trama d = bruno.pedido(Tipos.LEVANTAR, "bruno".getBytes(StandardCharsets.UTF_8));
            respostaGravada = Levantamento.resposta(d.corpo,
                    Chaves.assinar(brunoEd.getPrivate(), Levantamento.dadosAssinados("bruno", d.corpo)));
            bruno.pedido(Tipos.RESPOSTA, respostaGravada);
        }
        Thread.sleep(200); // o relay processa o fecho da ligacao

        // 2. A ana envia duas mensagens com o bruno desligado: ficam guardadas
        byte[] m1 = "envelope-1".getBytes(StandardCharsets.UTF_8);
        byte[] m2 = "envelope-2".getBytes(StandardCharsets.UTF_8);
        try (Cliente ana = new Cliente(porto)) {
            ana.pedido(Tipos.REGISTO, Registo.criar("ana", anaEd, anaX));
            Levantar.executar(ana::pedido, "ana", anaEd.getPrivate());
            verificar("Mensagem 1 guardada", ok(ana.pedido(Tipos.ENVIAR, corpoEnviar("bruno", m1)), "guardada"));
            verificar("Mensagem 2 guardada", ok(ana.pedido(Tipos.ENVIAR, corpoEnviar("bruno", m2)), "guardada"));
        }

        // 3. Ataque: so registar-se nao chega para receber nem para enviar
        try (Cliente mal = new Cliente(porto)) {
            mal.pedido(Tipos.REGISTO, Registo.criar("bruno", brunoEd, brunoX)); // repete o registo (e publico)
            Trama r = mal.pedido(Tipos.ENVIAR, corpoEnviar("ana", new byte[] {1}));
            verificar("REGISTO repetido nao autentica: ENVIAR recusado", r.tipo == Tipos.ERRO);
            verificar("...e nao recebeu as mensagens do bruno", mal.recebidas.isEmpty());
        }

        // 4. Ataque: levantar com a assinatura de outra chave
        try (Cliente mal = new Cliente(porto)) {
            recusado("Levantar com a assinatura de outro utilizador",
                    () -> Levantar.executar(mal::pedido, "bruno", malloryEd.getPrivate()));
            verificar("...e nao recebeu nenhuma mensagem", mal.recebidas.isEmpty());
        }

        // 5. Ataque: sem assinatura
        try (Cliente mal = new Cliente(porto)) {
            Trama d = mal.pedido(Tipos.LEVANTAR, "bruno".getBytes(StandardCharsets.UTF_8));
            Trama r = mal.pedido(Tipos.RESPOSTA, Levantamento.resposta(d.corpo, new byte[0]));
            verificar("Resposta sem assinatura recusada", r.tipo == Tipos.ERRO && mal.recebidas.isEmpty());
        }

        // 6. Ataque: repetir a resposta gravada no passo 1, numa ligacao nova
        try (Cliente mal = new Cliente(porto)) {
            mal.pedido(Tipos.LEVANTAR, "bruno".getBytes(StandardCharsets.UTF_8));
            Trama r = mal.pedido(Tipos.RESPOSTA, respostaGravada);
            verificar("Resposta gravada repetida recusada", r.tipo == Tipos.ERRO && mal.recebidas.isEmpty());
        }

        // 7. O bruno legitimo volta (mesmas chaves) e levanta as duas, pela ordem
        try (Cliente bruno = new Cliente(porto)) {
            bruno.pedido(Tipos.REGISTO, Registo.criar("bruno", brunoEd, brunoX));
            int n = Levantar.executar(bruno::pedido, "bruno", brunoEd.getPrivate());
            verificar("Bruno levanta 2 pendentes", n == 2 && bruno.recebidas.size() == 2);
            verificar("...pela ordem certa e sem alteracoes",
                    bruno.recebidas.size() == 2
                            && Arrays.equals(bruno.recebidas.get(0), m1)
                            && Arrays.equals(bruno.recebidas.get(1), m2));

            // 8. Depois de levantadas, as pendentes foram apagadas
            int outra = Levantar.executar(bruno::pedido, "bruno", brunoEd.getPrivate());
            verificar("Segundo levantamento devolve 0", outra == 0);

            // 9. Ja autenticado, uma mensagem nova chega em direto
            try (Cliente ana = new Cliente(porto)) {
                ana.pedido(Tipos.REGISTO, Registo.criar("ana", anaEd, anaX));
                Levantar.executar(ana::pedido, "ana", anaEd.getPrivate());
                byte[] m3 = "envelope-3".getBytes(StandardCharsets.UTF_8);
                verificar("Com o bruno autenticado: entregue em direto",
                        ok(ana.pedido(Tipos.ENVIAR, corpoEnviar("bruno", m3)), "entregue"));
                Trama t = Trama.ler(bruno.in);
                verificar("...e o bruno recebeu-a", t.tipo == Tipos.ENTREGA && Arrays.equals(t.corpo, m3));
            }
        }

        servidor.close();
        System.out.println(falhas == 0 ? "\nTodos os testes passaram." : "\n" + falhas + " teste(s) falharam.");
        System.exit(falhas == 0 ? 0 : 1);
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

    interface Acao { Object executar() throws Exception; }

    static void recusado(String descricao, Acao acao) {
        try {
            acao.executar();
            falhas++;
            System.out.println("FALHOU  " + descricao + " -> ACEITE");
        } catch (Exception e) {
            System.out.println("PASSOU  " + descricao + " -> recusado (" + e.getMessage() + ")");
        }
    }

    static void verificar(String descricao, boolean ok) {
        if (!ok) {
            falhas++;
        }
        System.out.println((ok ? "PASSOU  " : "FALHOU  ") + descricao);
    }
}