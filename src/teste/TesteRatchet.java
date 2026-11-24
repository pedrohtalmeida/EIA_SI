package teste;

import common.CadeiaChaves;
import common.Chaves;
import common.Cifra;
import common.Hkdf;
import common.Mensagem;
import common.Registo;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;

public class TesteRatchet {

    public static void main(String[] args) throws Exception {
        KeyPair anaAssinatura = Chaves.gerarParAssinatura();
        KeyPair anaAcordo = Chaves.gerarParAcordo();
        Registo regAna = Registo.ler(Registo.criar("ana", anaAssinatura, anaAcordo));

        KeyPair brunoAssinatura = Chaves.gerarParAssinatura();
        KeyPair brunoAcordo = Chaves.gerarParAcordo();
        Registo regBruno = Registo.ler(Registo.criar("bruno", brunoAssinatura, brunoAcordo));

        // 1. Mensagens fora de ordem (chega #2, depois #0, depois #1)
        CadeiaChaves envioAna = CadeiaChaves.criarParaEnvio(
                anaAcordo.getPrivate(), brunoAcordo.getPublic(), "ana", "bruno");
        CadeiaChaves rececaoBruno = CadeiaChaves.criarComSessao(
                envioAna.getIdSessao(), brunoAcordo.getPrivate(), anaAcordo.getPublic(), "ana", "bruno");

        byte[] env0 = Mensagem.selar("ana", anaAssinatura, envioAna, regBruno, "Msg 0");
        byte[] env1 = Mensagem.selar("ana", anaAssinatura, envioAna, regBruno, "Msg 1");
        byte[] env2 = Mensagem.selar("ana", anaAssinatura, envioAna, regBruno, "Msg 2");

        // Bruno recebe #2 primeiro -> salta #0 e #1 (guarda 2 chaves saltadas)
        String dec2 = Mensagem.ler(env2).abrir("bruno", rececaoBruno, regAna);
        if (!"Msg 2".equals(dec2) || rececaoBruno.getTotalSaltadas() != 2) {
            throw new AssertionError("Falha ao processar mensagem fora de ordem (#2).");
        }

        // Bruno recebe #0 depois -> usa a chave saltada 0 e apaga-a
        String dec0 = Mensagem.ler(env0).abrir("bruno", rececaoBruno, regAna);
        if (!"Msg 0".equals(dec0) || rececaoBruno.getTotalSaltadas() != 1) {
            throw new AssertionError("Falha ao decifrar mensagem atrasada (#0).");
        }

        // 2. Mensagem repetida (#0 enviada segunda vez) deve ser rejeitada
        try {
            Mensagem.ler(env0).abrir("bruno", rececaoBruno, regAna);
            throw new AssertionError("Mensagem repetida (#0) devia ter sido rejeitada!");
        } catch (GeneralSecurityException esperado) {
            // OK
        }

        // Bruno recebe #1 -> usa a última chave saltada
        String dec1 = Mensagem.ler(env1).abrir("bruno", rececaoBruno, regAna);
        if (!"Msg 1".equals(dec1) || rececaoBruno.getTotalSaltadas() != 0) {
            throw new AssertionError("Falha ao decifrar mensagem atrasada (#1).");
        }

        // 3. Forward Secrecy: a chave de cadeia atual (CK_3) não permite derivar MK_0 nem decifrar Msg 0
        byte[] ckAtual = rececaoBruno.copiarChaveCadeiaAtualParaTeste();
        byte[] mkFalsaDaCkAtual = Hkdf.expand(ckAtual, "msg-key".getBytes(StandardCharsets.UTF_8), 32);
        try {
            // Tenta decifrar um bloco cifrado com MK_0 usando a chave derivada de CK_3
            byte[] iv = Cifra.novoIv();
            CadeiaChaves c1 = CadeiaChaves.criarParaEnvio(
                    anaAcordo.getPrivate(), brunoAcordo.getPublic(), "ana", "bruno");
            byte[] mk0Real = c1.avancarParaEnvio().chaveMensagem;
            byte[] cifradoComMk0 = Cifra.cifrar(mk0Real, iv, "secreto".getBytes(StandardCharsets.UTF_8), new byte[0]);
            Cifra.decifrar(mkFalsaDaCkAtual, iv, cifradoComMk0, new byte[0]);
            throw new AssertionError("A chave de cadeia atual nao devia conseguir decifrar mensagens anteriores!");
        } catch (GeneralSecurityException esperado) {
            // OK - AES-GCM falha a autenticação porque MK_3 != MK_0
        }

        // 4. Ultrapassar o limite de chaves saltadas (LIMITE_SALTADAS = 50) é recusado
        CadeiaChaves envioLimite = CadeiaChaves.criarParaEnvio(
                anaAcordo.getPrivate(), brunoAcordo.getPublic(), "ana", "bruno");
        CadeiaChaves rececaoLimite = CadeiaChaves.criarComSessao(
                envioLimite.getIdSessao(), brunoAcordo.getPrivate(), anaAcordo.getPublic(), "ana", "bruno");

        // Avança 52 mensagens sem entregar nenhuma (saltaria 51 mensagens -> excede 50)
        byte[] ultima = null;
        for (int i = 0; i <= CadeiaChaves.LIMITE_SALTADAS + 1; i++) {
            ultima = Mensagem.selar("ana", anaAssinatura, envioLimite, regBruno, "Msg " + i);
        }
        try {
            Mensagem.ler(ultima).abrir("bruno", rececaoLimite, regAna);
            throw new AssertionError("Ultrapassar o limite de chaves saltadas devia ser recusado!");
        } catch (GeneralSecurityException esperado) {
            // OK
        }

        System.out.println("OK - TesteRatchet passou (fora de ordem, repeticao, forward secrecy e limite).");
    }
}