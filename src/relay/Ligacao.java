package relay;

import common.Tipos;
import common.Trama;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/*
 Envolve o fluxo de saida de um cliente. 'synchronized' porque varias threads
 podem escrever para o mesmo cliente ao mesmo tempo (a dele, ao responder,
 e a de outro cliente, ao entregar-lhe uma mensagem). Sem isto, os bytes de
 duas tramas podiam ficar misturados.
 
 (Estava dentro do RelayMain; passou para um ficheiro proprio porque a
 classe Pendentes tambem precisa dela.)
 */
public final class Ligacao {

    private final DataOutputStream out;

    public Ligacao(DataOutputStream out) {
        this.out = out;
    }

    public synchronized void enviar(byte tipo, byte[] corpo) throws IOException {
        Trama.escrever(out, tipo, corpo);
    }

    public void erro(String mensagem) throws IOException {
        enviar(Tipos.ERRO, mensagem.getBytes(StandardCharsets.UTF_8));
    }
}