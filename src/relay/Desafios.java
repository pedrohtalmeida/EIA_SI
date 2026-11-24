package relay;

import common.Chaves;
import common.Levantamento;
import common.Registo;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/*
 A2 - Modulo C: desafios do levantamento por desafio-resposta.
 
  1. O cliente pede para levantar as mensagens de 'nome'.
  2. O relay gera um nonce de 32 bytes com SecureRandom e guarda-o, associado
     a essa ligacao e a esse nome, com validade curta.
  3. O cliente devolve o nonce e a assinatura Ed25519 de
     Levantamento.dadosAssinados(nome, nonce).
  4. O relay RETIRA o desafio da tabela (uso unico: mesmo que a verificacao
     falhe, aquele nonce nunca mais e aceite), confirma a validade e verifica
     a assinatura com a chave publica REGISTADA desse nome.
 
  Ha no maximo um desafio pendente por ligacao: pedir outro substitui o
  anterior. Assim um cliente nao consegue encher a memoria com desafios.
 */
public final class Desafios {

    private static final SecureRandom RNG = new SecureRandom();

    private record Pendente(String nome, byte[] nonce, long expiraEm) {}

    private final long validadeMs;
    private final ConcurrentHashMap<Object, Pendente> pendentes = new ConcurrentHashMap<>();

    public Desafios(long validadeMs) {
        this.validadeMs = validadeMs;
    }

    // 'dono' identifica a ligacao a que o desafio pertence (no relay, o objeto Ligacao).
    public byte[] novo(Object dono, String nome) {
        byte[] nonce = new byte[Levantamento.TAM_NONCE];
        RNG.nextBytes(nonce);
        pendentes.put(dono, new Pendente(nome, nonce, System.currentTimeMillis() + validadeMs));
        return nonce.clone();
    }

    /*
     Verifica a resposta. Devolve o nome do utilizador autenticado, ou lanca
     GeneralSecurityException com o motivo da recusa.
     'registos' da o registo (com a chave publica) de cada nome.
     */
    public String verificar(Object dono, byte[] nonce, byte[] assinatura, Function<String, Registo> registos)
            throws GeneralSecurityException {
        Pendente p = pendentes.remove(dono); // consumido ja: uso unico
        if (p == null) {
            throw new GeneralSecurityException("Nenhum desafio pendente (desafio repetido ou nao pedido)");
        }
        if (System.currentTimeMillis() > p.expiraEm()) {
            throw new GeneralSecurityException("Desafio expirado");
        }
        if (!MessageDigest.isEqual(p.nonce(), nonce)) { // comparacao em tempo constante
            throw new GeneralSecurityException("A resposta nao corresponde ao desafio emitido");
        }
        Registo r = registos.apply(p.nome());
        if (r == null) {
            throw new GeneralSecurityException("Utilizador desconhecido");
        }
        if (assinatura.length == 0
                || !Chaves.verificar(r.chaveAssinatura, Levantamento.dadosAssinados(p.nome(), p.nonce()), assinatura)) {
            throw new GeneralSecurityException("Assinatura invalida");
        }
        return p.nome();
    }

    // Quando a ligacao fecha, o desafio pendente dela deixa de valer.
    public void esquecer(Object dono) {
        pendentes.remove(dono);
    }
}