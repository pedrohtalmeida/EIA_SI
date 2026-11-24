package teste;

import common.Chaves;
import common.Levantamento;
import common.Registo;
import java.security.KeyPair;
import java.util.Map;
import relay.Desafios;

/* Modulo C (A2): testa a classe Desafios do relay, sem rede. */
public class TesteDesafios {

    private static int falhas = 0;

    public static void main(String[] args) throws Exception {
        KeyPair anaEd = Chaves.gerarParAssinatura(), anaX = Chaves.gerarParAcordo();
        KeyPair carlosEd = Chaves.gerarParAssinatura(), carlosX = Chaves.gerarParAcordo();
        Map<String, Registo> registos = Map.of(
                "ana", Registo.ler(Registo.criar("ana", anaEd, anaX)),
                "carlos", Registo.ler(Registo.criar("carlos", carlosEd, carlosX)));

        Desafios desafios = new Desafios(30_000);

        // 1. Caso valido
        Object lig1 = new Object();
        byte[] nonce = desafios.novo(lig1, "ana");
        byte[] assinatura = Chaves.assinar(anaEd.getPrivate(), Levantamento.dadosAssinados("ana", nonce));
        aceite("Resposta valida da Ana", () -> desafios.verificar(lig1, nonce, assinatura, registos::get));

        // 2. Desafio repetido: a mesma resposta, outra vez
        recusado("Desafio repetido (mesma resposta duas vezes)",
                () -> desafios.verificar(lig1, nonce, assinatura, registos::get));

        // 3. Sem assinatura
        Object lig2 = new Object();
        byte[] n2 = desafios.novo(lig2, "ana");
        recusado("Sem assinatura", () -> desafios.verificar(lig2, n2, new byte[0], registos::get));

        // 4. Assinatura de outro utilizador: o Carlos assina o desafio da Ana com a chave dele
        Object lig3 = new Object();
        byte[] n3 = desafios.novo(lig3, "ana");
        byte[] assCarlos = Chaves.assinar(carlosEd.getPrivate(), Levantamento.dadosAssinados("ana", n3));
        recusado("Assinatura de outro utilizador", () -> desafios.verificar(lig3, n3, assCarlos, registos::get));

        // 5. Resposta antiga reaproveitada num desafio novo (repeticao gravada da rede)
        Object lig4 = new Object();
        desafios.novo(lig4, "ana");
        recusado("Resposta antiga num desafio novo", () -> desafios.verificar(lig4, nonce, assinatura, registos::get));

        // 6. Assinatura sem o texto de contexto (feita para outra parte do protocolo)
        Object lig5 = new Object();
        byte[] n5 = desafios.novo(lig5, "ana");
        byte[] semContexto = Chaves.assinar(anaEd.getPrivate(), n5);
        recusado("Assinatura so do nonce, sem contexto", () -> desafios.verificar(lig5, n5, semContexto, registos::get));

        // 7. Desafio expirado
        Desafios curtos = new Desafios(50);
        Object lig6 = new Object();
        byte[] n6 = curtos.novo(lig6, "ana");
        byte[] a6 = Chaves.assinar(anaEd.getPrivate(), Levantamento.dadosAssinados("ana", n6));
        Thread.sleep(120);
        recusado("Desafio expirado", () -> curtos.verificar(lig6, n6, a6, registos::get));

        System.out.println(falhas == 0 ? "\nTodos os testes passaram." : "\n" + falhas + " teste(s) falharam.");
        System.exit(falhas == 0 ? 0 : 1);
    }

    interface Acao { Object executar() throws Exception; }

    static void aceite(String descricao, Acao acao) {
        try {
            acao.executar();
            System.out.println("PASSOU  " + descricao + " -> aceite");
        } catch (Exception e) {
            falhas++;
            System.out.println("FALHOU  " + descricao + " -> recusado: " + e.getMessage());
        }
    }

    static void recusado(String descricao, Acao acao) {
        try {
            acao.executar();
            falhas++;
            System.out.println("FALHOU  " + descricao + " -> ACEITE");
        } catch (Exception e) {
            System.out.println("PASSOU  " + descricao + " -> recusado (" + e.getMessage() + ")");
        }
    }
}