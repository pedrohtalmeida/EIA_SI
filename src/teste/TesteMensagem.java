package teste;

import common.CadeiaChaves;
import common.Chaves;
import common.Mensagem;
import common.Registo;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

/*
 * Ameacas A1, A2 e A3: o envelope so revela o conteudo ao destinatario (A1), qualquer
 * alteracao de um byte e detetada (A2) e uma mensagem nao pode ser atribuida a quem
 * nao a assinou (A3).
 */
public class TesteMensagem {

    static boolean tudoOk = true;

    public static void main(String[] args) throws Exception {
        KeyPair anaAss = Chaves.gerarParAssinatura(), anaAc = Chaves.gerarParAcordo();
        KeyPair brunoAss = Chaves.gerarParAssinatura(), brunoAc = Chaves.gerarParAcordo();
        KeyPair carlaAss = Chaves.gerarParAssinatura(), carlaAc = Chaves.gerarParAcordo();
        KeyPair malAss = Chaves.gerarParAssinatura(), malAc = Chaves.gerarParAcordo();

        Registo regAna = Registo.ler(Registo.criar("ana", anaAss, anaAc));
        Registo regBruno = Registo.ler(Registo.criar("bruno", brunoAss, brunoAc));
        Registo regCarla = Registo.ler(Registo.criar("carla", carlaAss, carlaAc));

        String texto = "texto muito secreto: 1234-5678";
        CadeiaChaves envio = CadeiaChaves.criarParaEnvio(anaAc.getPrivate(), regBruno.chaveAcordo, "ana", "bruno");
        byte[] envelope = Mensagem.selar("ana", anaAss, envio, regBruno, texto);

        // A1: o texto nao aparece em claro e o destinatario consegue le-lo
        verificar("A1: o texto nao aparece em claro no envelope",
                !contem(envelope, texto.getBytes(StandardCharsets.UTF_8))
                        && !contem(envelope, "secreto".getBytes(StandardCharsets.UTF_8)));
        Mensagem m = Mensagem.ler(envelope);
        CadeiaChaves rec = CadeiaChaves.criarComSessao(m.idSessao, brunoAc.getPrivate(), regAna.chaveAcordo, "ana", "bruno");
        verificar("A1: o destinatario decifra o envelope", texto.equals(m.abrir("bruno", rec, regAna)));

        // A1: quem nao e o destinatario (a carla, ou o relay com chaves proprias) nao consegue abri-lo
        Mensagem m2 = Mensagem.ler(envelope);
        CadeiaChaves recCarla = CadeiaChaves.criarComSessao(m2.idSessao, carlaAc.getPrivate(), regAna.chaveAcordo, "ana", "bruno");
        verificar("A1: a carla nao consegue abrir o envelope do bruno", rejeitado(() -> m2.abrir("bruno", recCarla, regAna)));
        verificar("A1: e a carla nem o aceita como sendo para ela", rejeitado(() -> m2.abrir("carla", recCarla, regAna)));

        // A2: alterar qualquer bit de qualquer byte do envelope tem de ser detetado
        int aceites = 0;
        for (int i = 0; i < envelope.length; i++) {
            byte[] adulterado = envelope.clone();
            adulterado[i] ^= 0x01;
            try {
                Mensagem t = Mensagem.ler(adulterado);
                CadeiaChaves c = CadeiaChaves.criarComSessao(m.idSessao, brunoAc.getPrivate(), regAna.chaveAcordo, "ana", "bruno");
                t.abrir("bruno", c, regAna);
                aceites++;
            } catch (Exception e) {
                // rejeitado, como esperado
            }
        }
        verificar("A2: " + envelope.length + " alteracoes de 1 bit (uma por byte): " + aceites + " aceites", aceites == 0);

        // A2: truncar ou acrescentar bytes
        verificar("A2: envelope truncado e rejeitado", rejeitadoLer(java.util.Arrays.copyOf(envelope, envelope.length - 1), m, brunoAc, regAna));
        byte[] maisUm = java.util.Arrays.copyOf(envelope, envelope.length + 1);
        verificar("A2: envelope com um byte a mais e rejeitado", rejeitadoLer(maisUm, m, brunoAc, regAna));

        // A3: a mallory assina com a chave dela uma mensagem que diz ser da ana
        CadeiaChaves cadeiaMal = CadeiaChaves.criarParaEnvio(malAc.getPrivate(), regBruno.chaveAcordo, "ana", "bruno");
        byte[] falsa = Mensagem.selar("ana", malAss, cadeiaMal, regBruno, "transferir 100 euros");
        Mensagem mf = Mensagem.ler(falsa);
        CadeiaChaves recFalsa = CadeiaChaves.criarComSessao(mf.idSessao, brunoAc.getPrivate(), regAna.chaveAcordo, "ana", "bruno");
        String motivo = motivo(() -> mf.abrir("bruno", recFalsa, regAna));
        verificar("A3: mensagem assinada por outra pessoa em nome da ana e rejeitada (" + motivo + ")",
                motivo != null && motivo.contains("Assinatura"));

        // A3: o registo que se usa para verificar tem de ser o do remetente indicado
        Mensagem m3 = Mensagem.ler(envelope);
        CadeiaChaves rec3 = CadeiaChaves.criarComSessao(m3.idSessao, brunoAc.getPrivate(), regAna.chaveAcordo, "ana", "bruno");
        verificar("A3: registo de outro utilizador nao serve para verificar a mensagem da ana",
                rejeitado(() -> m3.abrir("bruno", rec3, regCarla)));

        // A6 (mesma sessao): o mesmo envelope nao e aceite duas vezes
        Mensagem m4 = Mensagem.ler(envelope);
        CadeiaChaves rec4 = CadeiaChaves.criarComSessao(m4.idSessao, brunoAc.getPrivate(), regAna.chaveAcordo, "ana", "bruno");
        boolean primeira = texto.equals(m4.abrir("bruno", rec4, regAna));
        verificar("A6: 1.a entrega aceite e repeticao do mesmo envelope rejeitada",
                primeira && rejeitado(() -> m4.abrir("bruno", rec4, regAna)));

        System.out.println(tudoOk ? "OK - TesteMensagem passou." : "HA FALHAS no TesteMensagem.");
        if (!tudoOk) System.exit(1);
    }

    private interface Acao { void correr() throws Exception; }

    private static boolean rejeitado(Acao a) {
        return motivo(a) != null;
    }

    // Devolve a mensagem da excecao, ou null se a acao foi aceite.
    private static String motivo(Acao a) {
        try {
            a.correr();
            return null;
        } catch (Exception e) {
            return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        }
    }

    private static boolean rejeitadoLer(byte[] env, Mensagem original, KeyPair brunoAc, Registo regAna) {
        return rejeitado(() -> {
            Mensagem t = Mensagem.ler(env);
            CadeiaChaves c = CadeiaChaves.criarComSessao(original.idSessao, brunoAc.getPrivate(), regAna.chaveAcordo, "ana", "bruno");
            t.abrir("bruno", c, regAna);
        });
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
