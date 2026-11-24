package teste;

import client.GestorCadeias;
import client.Identidade;
import common.CadeiaChaves;
import common.Chaves;
import common.Mensagem;
import common.Registo;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/*
 * Testa a persistencia das cadeias de rececao e a protecao contra repeticoes
 * (reinicio do cliente, varias sessoes do mesmo remetente, ficheiro adulterado).
 */
public class TesteGestorCadeias {

    static Identidade ana, bruno;
    static Registo regAna, regBruno;
    static boolean tudoOk = true;

    public static void main(String[] args) throws Exception {
        Path pasta = Files.createTempDirectory("cadeias-teste");
        ana = new Identidade("ana", Chaves.gerarParAssinatura(), Chaves.gerarParAcordo());
        bruno = new Identidade("bruno", Chaves.gerarParAssinatura(), Chaves.gerarParAcordo());
        regAna = Registo.ler(Registo.criar("ana", ana.getAssinaturaEd25519(), ana.getAcordoX25519()));
        regBruno = Registo.ler(Registo.criar("bruno", bruno.getAssinaturaEd25519(), bruno.getAcordoX25519()));
        Path ficheiro = pasta.resolve("bruno.cadeias");

        // 1. Reinicio a meio de uma conversa longa (problema 1)
        CadeiaChaves envio = novaCadeiaEnvio();
        List<byte[]> env = new ArrayList<>();
        for (int i = 0; i < 61; i++) env.add(Mensagem.selar("ana", ana.getAssinaturaEd25519(), envio, regBruno, "msg " + i));

        GestorCadeias g = GestorCadeias.carregar(ficheiro, bruno);
        for (int i = 0; i < 60; i++) entregar(g, env.get(i));
        GestorCadeias reiniciado = GestorCadeias.carregar(ficheiro, bruno); // "bruno reiniciou"
        String r = tentar(reiniciado, env.get(60));
        verificar("Apos reinicio, a mensagem 60 e aceite", "msg 60".equals(r));

        // 2. Repeticao depois do reinicio (problema 1, segunda parte)
        verificar("Apos reinicio, repeticao da mensagem 0 rejeitada", tentar(reiniciado, env.get(0)) == null);
        verificar("Apos reinicio, repeticao da mensagem 59 rejeitada", tentar(reiniciado, env.get(59)) == null);

        // 3. Duas sessoes do mesmo remetente e repeticao da antiga (problema 2)
        Path f2 = pasta.resolve("bruno2.cadeias");
        GestorCadeias g2 = GestorCadeias.carregar(f2, bruno);
        byte[] antiga = Mensagem.selar("ana", ana.getAssinaturaEd25519(), novaCadeiaEnvio(), regBruno, "transferir 100 euros");
        byte[] nova = Mensagem.selar("ana", ana.getAssinaturaEd25519(), novaCadeiaEnvio(), regBruno, "ola");
        verificar("Sessao A aceite", "transferir 100 euros".equals(tentar(g2, antiga)));
        verificar("Sessao B aceite", "ola".equals(tentar(g2, nova)));
        verificar("Repeticao da sessao A rejeitada (outra sessao entretanto)", tentar(g2, antiga) == null);
        verificar("Repeticao da sessao B rejeitada", tentar(g2, nova) == null);
        verificar("Duas cadeias guardadas (uma por sessao)", g2.tamanho() == 2);

        // 4. O estado sobrevive ao reinicio com varias sessoes
        GestorCadeias g2b = GestorCadeias.carregar(f2, bruno);
        verificar("Apos reinicio, repeticao da sessao A continua rejeitada", tentar(g2b, antiga) == null);
        verificar("Apos reinicio, repeticao da sessao B continua rejeitada", tentar(g2b, nova) == null);

        // 5. O conteudo esta cifrado: o cabecalho do formato nao aparece em claro
        byte[] ficheiroBytes = Files.readAllBytes(f2);
        verificar("O ficheiro esta cifrado (cabecalho do formato nao aparece em claro)",
                !contem(ficheiroBytes, "EIASICADEIAS1".getBytes()));

        // 6. Ficheiro adulterado e detetado
        byte[] adulterado = ficheiroBytes.clone();
        adulterado[adulterado.length - 3] ^= 0x01;
        Path f3 = pasta.resolve("adulterado.cadeias");
        Files.write(f3, adulterado);
        verificar("Ficheiro adulterado detetado", falha(() -> GestorCadeias.carregar(f3, bruno)));

        // 7. Outra identidade nao consegue abrir o ficheiro
        verificar("Ficheiro do bruno nao abre com a identidade da ana", falha(() -> GestorCadeias.carregar(f2, ana)));

        // 8. Limite de sessoes guardadas
        Path f4 = pasta.resolve("limite.cadeias");
        GestorCadeias g4 = GestorCadeias.carregar(f4, bruno);
        for (int i = 0; i < GestorCadeias.MAX_SESSOES + 20; i++) {
            tentar(g4, Mensagem.selar("ana", ana.getAssinaturaEd25519(), novaCadeiaEnvio(), regBruno, "s" + i));
        }
        verificar("Limite de " + GestorCadeias.MAX_SESSOES + " sessoes respeitado (tem " + g4.tamanho() + ")",
                g4.tamanho() == GestorCadeias.MAX_SESSOES);
        verificar("O ficheiro com o limite recarrega",
                GestorCadeias.carregar(f4, bruno).tamanho() == GestorCadeias.MAX_SESSOES);

        System.out.println(tudoOk ? "OK - TesteGestorCadeias passou." : "HA FALHAS no TesteGestorCadeias.");
        if (!tudoOk) System.exit(1);
    }

    private static CadeiaChaves novaCadeiaEnvio() throws Exception {
        return CadeiaChaves.criarParaEnvio(ana.getAcordoX25519().getPrivate(), regBruno.chaveAcordo, "ana", "bruno");
    }

    // Logica do ClientMain.receber: obter cadeia da sessao, abrir, guardar. Devolve o texto ou null se rejeitada.
    private static String tentar(GestorCadeias g, byte[] envelope) {
        try {
            Mensagem m = Mensagem.ler(envelope);
            CadeiaChaves c = g.obter(regAna, m.idSessao, bruno.getAcordoX25519().getPrivate(), "bruno");
            try {
                return m.abrir("bruno", c, regAna);
            } finally {
                g.guardar();
            }
        } catch (Exception e) {
            return null;
        }
    }

    private static void entregar(GestorCadeias g, byte[] envelope) {
        if (tentar(g, envelope) == null) {
            throw new IllegalStateException("Mensagem normal rejeitada");
        }
    }

    private interface Acao { void correr() throws Exception; }

    private static boolean falha(Acao a) {
        try { a.correr(); return false; } catch (Exception e) { return true; }
    }

    private static boolean contem(byte[] dentro, byte[] procurado) {
        for (int i = 0; i + procurado.length <= dentro.length; i++) {
            boolean igual = true;
            for (int j = 0; j < procurado.length && igual; j++) igual = dentro[i + j] == procurado[j];
            if (igual) return true;
        }
        return false;
    }

    private static void verificar(String nome, boolean ok) {
        System.out.println((ok ? "OK      " : "FALHOU  ") + nome);
        tudoOk &= ok;
    }
}
