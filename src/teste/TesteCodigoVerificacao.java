package teste;

import client.Contactos;
import client.Identidade;
import common.Chaves;
import common.Registo;

import java.nio.file.Files;
import java.nio.file.Path;

/*
 * Verifica que o codigo que cada utilizador calcula para si proprio (comando meucodigo)
 * coincide com o que o contacto ve (comando verificar), e que muda se a chave mudar.
 */
public class TesteCodigoVerificacao {

    static boolean tudoOk = true;

    public static void main(String[] args) throws Exception {
        Path pasta = Files.createTempDirectory("codigo-teste");
        Identidade ana = new Identidade("ana", Chaves.gerarParAssinatura(), Chaves.gerarParAcordo());
        Identidade bruno = new Identidade("bruno", Chaves.gerarParAssinatura(), Chaves.gerarParAcordo());

        Registo regAna = Registo.ler(Registo.criar("ana", ana.getAssinaturaEd25519(), ana.getAcordoX25519()));

        // O que a Ana ve com 'meucodigo' (so com as suas chaves locais)
        String codigoDaAna = Contactos.gerarCodigoVerificacao(Contactos.calcularImpressaoDigital(regAna));

        // O que o Bruno ve com 'verificar ana' (depois de obter o registo da Ana e fazer TOFU)
        Contactos contactosBruno = Contactos.carregar(pasta.resolve("bruno.contactos"), bruno);
        contactosBruno.verificarOuRegistarTofu(regAna);
        String codigoVistoPeloBruno = contactosBruno.obterCodigoVerificacao("ana");

        System.out.println("Ana (meucodigo):          " + codigoDaAna);
        System.out.println("Bruno (verificar ana):    " + codigoVistoPeloBruno);
        verificar("Os dois codigos sao iguais", codigoDaAna.equals(codigoVistoPeloBruno));
        verificar("Formato 0000-0000-0000", codigoDaAna.matches("\\d{4}-\\d{4}-\\d{4}"));

        // Outra pessoa tem outro codigo
        Registo regBruno = Registo.ler(Registo.criar("bruno", bruno.getAssinaturaEd25519(), bruno.getAcordoX25519()));
        String codigoDoBruno = Contactos.gerarCodigoVerificacao(Contactos.calcularImpressaoDigital(regBruno));
        verificar("Pessoas diferentes tem codigos diferentes", !codigoDaAna.equals(codigoDoBruno));

        // Se um atacante (ou o relay) servir outra chave com o nome 'ana', o codigo muda
        Identidade impostor = new Identidade("ana", Chaves.gerarParAssinatura(), Chaves.gerarParAcordo());
        Registo regFalso = Registo.ler(Registo.criar("ana", impostor.getAssinaturaEd25519(), impostor.getAcordoX25519()));
        String codigoFalso = Contactos.gerarCodigoVerificacao(Contactos.calcularImpressaoDigital(regFalso));
        verificar("Uma chave falsa com o nome 'ana' da um codigo diferente", !codigoDaAna.equals(codigoFalso));

        System.out.println(tudoOk ? "OK - TesteCodigoVerificacao passou." : "HA FALHAS.");
        if (!tudoOk) System.exit(1);
    }

    private static void verificar(String nome, boolean ok) {
        System.out.println((ok ? "OK      " : "FALHOU  ") + nome);
        tudoOk &= ok;
    }
}
