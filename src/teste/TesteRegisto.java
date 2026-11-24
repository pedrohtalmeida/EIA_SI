package teste;

import common.Chaves;
import common.Registo;
import common.Tipos;
import common.Trama;
import relay.RelayMain;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;

/*
 * Ameaca A4: o relay nao deixa registar um nome ja ocupado com outra chave, recusa
 * registos com assinatura invalida e continua a devolver o registo original.
 */
public class TesteRegisto {

    static boolean tudoOk = true;

    static final class Cliente implements AutoCloseable {
        final Socket s;
        final DataInputStream in;
        final DataOutputStream out;

        Cliente(int porto) throws IOException {
            s = new Socket("localhost", porto);
            s.setSoTimeout(5000);
            in = new DataInputStream(s.getInputStream());
            out = new DataOutputStream(s.getOutputStream());
        }

        Trama pedido(byte tipo, byte[] corpo) throws IOException {
            Trama.escrever(out, tipo, corpo);
            return Trama.ler(in);
        }

        public void close() throws IOException { s.close(); }
    }

    public static void main(String[] args) throws Exception {
        ServerSocket servidor = new ServerSocket(0);
        Thread relay = new Thread(() -> {
            try { RelayMain.servir(servidor); } catch (IOException e) { /* fecha no fim */ }
        });
        relay.setDaemon(true);
        relay.start();
        int porto = servidor.getLocalPort();

        KeyPair ass1 = Chaves.gerarParAssinatura(), ac1 = Chaves.gerarParAcordo();
        KeyPair ass2 = Chaves.gerarParAssinatura(), ac2 = Chaves.gerarParAcordo();
        byte[] registoDona = Registo.criar("regtest", ass1, ac1);
        byte[] registoImpostor = Registo.criar("regtest", ass2, ac2);

        try (Cliente dona = new Cliente(porto); Cliente impostor = new Cliente(porto)) {
            Trama r1 = dona.pedido(Tipos.REGISTO, registoDona);
            verificar("A dona regista o nome 'regtest'", r1.tipo == Tipos.REGISTO_OK);

            Trama r2 = impostor.pedido(Tipos.REGISTO, registoImpostor);
            verificar("Outro cliente tenta o mesmo nome com outra chave: recusado ("
                    + texto(r2) + ")", r2.tipo == Tipos.ERRO && texto(r2).contains("outra chave"));

            Trama procura = impostor.pedido(Tipos.PROCURAR, "regtest".getBytes(StandardCharsets.UTF_8));
            verificar("PROCURAR continua a devolver o registo original da dona",
                    procura.tipo == Tipos.PROCURAR_RESP && Arrays.equals(procura.corpo, registoDona));
        }

        try (Cliente dona2 = new Cliente(porto)) {
            Trama r = dona2.pedido(Tipos.REGISTO, registoDona);
            verificar("A dona pode registar-se outra vez com a mesma chave (nova ligacao)", r.tipo == Tipos.REGISTO_OK);
        }

        // registo com um byte alterado (assinatura deixa de ser valida)
        byte[] adulterado = Registo.criar("regtest2", ass1, ac1);
        adulterado[adulterado.length - 80] ^= 0x01;
        try (Cliente c = new Cliente(porto)) {
            Trama r = c.pedido(Tipos.REGISTO, adulterado);
            verificar("Registo adulterado recusado (" + texto(r) + ")", r.tipo == Tipos.ERRO);
            Trama procura = c.pedido(Tipos.PROCURAR, "regtest2".getBytes(StandardCharsets.UTF_8));
            verificar("...e nada ficou registado", procura.tipo == Tipos.ERRO);
        }

        System.out.println(tudoOk ? "OK - TesteRegisto passou." : "HA FALHAS no TesteRegisto.");
        if (!tudoOk) System.exit(1);
    }

    private static String texto(Trama t) {
        return new String(t.corpo, StandardCharsets.UTF_8);
    }

    private static void verificar(String nome, boolean ok) {
        System.out.println((ok ? "OK      " : "FALHOU  ") + nome);
        tudoOk &= ok;
    }
}
