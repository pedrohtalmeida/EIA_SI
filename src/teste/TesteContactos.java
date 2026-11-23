package teste;

import client.Contactos;
import client.Identidade;
import common.Chaves;
import common.Registo;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Comparator;

public class TesteContactos {

    public static void main(String[] args) throws Exception {
        Path pastaTemp = Files.createTempDirectory("teste_contactos_");
        try {
            Path fichIdAna = pastaTemp.resolve("ana.id");
            Path fichContactosAna = pastaTemp.resolve("ana.contactos");

            Identidade idAna = Identidade.carregarOuCriar(fichIdAna, "ana", "passe-segura-123".toCharArray());
            Contactos contactosAna = Contactos.carregar(fichContactosAna, idAna);

            // Registo legítimo do Bruno
            KeyPair brunoAssinatura1 = Chaves.gerarParAssinatura();
            KeyPair brunoAcordo1 = Chaves.gerarParAcordo();
            Registo regBruno1 = Registo.ler(Registo.criar("bruno", brunoAssinatura1, brunoAcordo1));

            // 1. Primeira utilização (TOFU): deve registar e devolver true
            boolean primeira = contactosAna.verificarOuRegistarTofu(regBruno1);
            if (!primeira) {
                throw new AssertionError("Esperava true na primeira utilizacao (TOFU).");
            }

            // 2. Segunda utilização com a mesma chave: deve aceitar e devolver false
            boolean segunda = contactosAna.verificarOuRegistarTofu(regBruno1);
            if (segunda) {
                throw new AssertionError("Esperava false na segunda utilizacao com a mesma chave.");
            }

            String codigo1 = contactosAna.obterCodigoVerificacao("bruno");
            if (codigo1 == null || !codigo1.matches("\\d{4}-\\d{4}-\\d{4}")) {
                throw new AssertionError("Codigo de verificacao com formato invalido: " + codigo1);
            }

            // 3. Reabrir ficheiro de contactos numa nova sessão: mantém a chave e o mesmo código
            Contactos contactosRecarregados = Contactos.carregar(fichContactosAna, idAna);
            String codigo2 = contactosRecarregados.obterCodigoVerificacao("bruno");
            if (!codigo1.equals(codigo2)) {
                throw new AssertionError("Codigo de verificacao mudou apos recarregar o ficheiro!");
            }

            // 4. Chave alterada (ex.: relay malicioso ou nova identidade do Bruno): deve bloquear!
            KeyPair brunoAssinatura2 = Chaves.gerarParAssinatura();
            KeyPair brunoAcordo2 = Chaves.gerarParAcordo();
            Registo regBrunoFalso = Registo.ler(Registo.criar("bruno", brunoAssinatura2, brunoAcordo2));

            try {
                contactosRecarregados.verificarOuRegistarTofu(regBrunoFalso);
                throw new AssertionError("Chave alterada devia ter sido bloqueada pelo TOFU!");
            } catch (GeneralSecurityException esperado) {
                // OK
            }

            // 5. Adulterar 1 byte no ficheiro de contactos: HMAC deve detetar na abertura
            byte[] bytesFicheiro = Files.readAllBytes(fichContactosAna);
            bytesFicheiro[bytesFicheiro.length / 2] ^= 0x01;
            Files.write(fichContactosAna, bytesFicheiro);

            try {
                Contactos.carregar(fichContactosAna, idAna);
                throw new AssertionError("Ficheiro de contactos adulterado devia ter sido rejeitado!");
            } catch (GeneralSecurityException esperado) {
                // OK
            }

            System.out.println("OK - TesteContactos passou (TOFU, codigo " + codigo1 + ", bloqueio de chave alterada e HMAC).");
        } finally {
            Files.walk(pastaTemp)
                    .sorted(Comparator.reverseOrder())
                    .forEach(p -> {
                        try { Files.deleteIfExists(p); } catch (Exception ignored) {}
                    });
        }
    }
}