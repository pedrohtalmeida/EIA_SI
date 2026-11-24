package teste;

import client.Identidade;
import common.Chaves;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/*
 * Ameaca A8: o ficheiro dados/<nome>.id guarda as chaves privadas cifradas
 * (PBKDF2 + AES-256-GCM). Sem a palavra-passe certa nao abre, e qualquer
 * alteracao ao ficheiro ou troca entre utilizadores e detetada.
 */
public class TesteIdentidade {

    static boolean tudoOk = true;

    // A Identidade apaga o array da palavra-passe depois de o usar: cada chamada leva um novo.
    private static char[] pw(String s) { return s.toCharArray(); }

    public static void main(String[] args) throws Exception {
        Path pasta = Files.createTempDirectory("identidade-teste");
        Path ficheiro = pasta.resolve("ana.id");

        Identidade criada = Identidade.carregarOuCriar(ficheiro, "ana", pw("palavra-passe-certa"));
        verificar("Ficheiro de identidade criado", Files.exists(ficheiro));

        Identidade lida = Identidade.carregarOuCriar(ficheiro, "ana", pw("palavra-passe-certa"));
        verificar("Reabrir com a palavra-passe certa da as mesmas chaves publicas",
                Arrays.equals(criada.getAssinaturaEd25519().getPublic().getEncoded(), lida.getAssinaturaEd25519().getPublic().getEncoded())
                && Arrays.equals(criada.getAcordoX25519().getPublic().getEncoded(), lida.getAcordoX25519().getPublic().getEncoded()));

        byte[] dados = "teste".getBytes(StandardCharsets.UTF_8);
        byte[] ass = Chaves.assinar(lida.getAssinaturaEd25519().getPrivate(), dados);
        verificar("A chave privada carregada assina de forma valida",
                Chaves.verificar(criada.getAssinaturaEd25519().getPublic(), dados, ass));

        byte[] conteudo = Files.readAllBytes(ficheiro);
        byte[] privada = criada.getAssinaturaEd25519().getPrivate().getEncoded();
        byte[] chaveBruta = Arrays.copyOfRange(privada, privada.length - 32, privada.length);
        verificar("A chave privada nao aparece em claro no ficheiro", !contem(conteudo, chaveBruta));

        verificar("Palavra-passe errada recusada",
                recusado(() -> Identidade.carregarOuCriar(ficheiro, "ana", pw("palavra-passe-errada"))));

        verificar("Palavra-passe vazia recusada",
                recusado(() -> Identidade.carregarOuCriar(pasta.resolve("vazia.id"), "vazia", new char[0])));

        Identidade.carregarOuCriar(pasta.resolve("bruno.id"), "bruno", pw("palavra-passe-certa"));
        Files.copy(pasta.resolve("bruno.id"), pasta.resolve("carla.id"));
        verificar("O ficheiro do bruno nao abre como se fosse da carla",
                recusado(() -> Identidade.carregarOuCriar(pasta.resolve("carla.id"), "carla", pw("palavra-passe-certa"))));

        // alterar um bit em varias posicoes (cabecalho, sal, iv e texto cifrado): tem de falhar sempre
        int aceites = 0, tentativas = 0;
        for (int i = 0; i < conteudo.length; i += 7) {
            byte[] adulterado = conteudo.clone();
            adulterado[i] ^= 0x01;
            Path f = pasta.resolve("adulterado" + i + ".id");
            Files.write(f, adulterado);
            tentativas++;
            try {
                Identidade.carregarOuCriar(f, "ana", pw("palavra-passe-certa"));
                aceites++;
            } catch (Exception e) {
                // detetado
            }
        }
        verificar("Ficheiro adulterado detetado (" + tentativas + " alteracoes, " + aceites + " aceites)", aceites == 0);

        System.out.println(tudoOk ? "OK - TesteIdentidade passou." : "HA FALHAS no TesteIdentidade.");
        if (!tudoOk) System.exit(1);
    }

    private interface Acao { void correr() throws Exception; }

    private static boolean recusado(Acao a) {
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
