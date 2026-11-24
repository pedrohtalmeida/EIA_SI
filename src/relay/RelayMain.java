package relay;

import common.Bytes;
import common.Levantamento;
import common.Registo;
import common.Tipos;
import common.Trama;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;


/*
 * Relay: regista utilizadores, responde a pedidos de descoberta e reencaminha
 * envelopes cifrados. Nunca tem acesso as chaves privadas nem ao texto das mensagens.
 */
public class RelayMain {

    public static final int PORTO_PREDEFINIDO = 5000;

    // nome -> registo (chaves publicas). Partilhado por todas as threads.
    private static final ConcurrentHashMap<String, Registo> utilizadores = new ConcurrentHashMap<>();

    // Ligacao ativa de cada utilizador + mensagens pendentes (armazenamento diferido).
    private static final Pendentes pendentes = new Pendentes();

    
    // Modulo C: desafios do levantamento, validos durante 30 segundos.
    public static final long VALIDADE_DESAFIO_MS = 30_000;
    private static final Desafios desafios = new Desafios(VALIDADE_DESAFIO_MS);

   public static void main(String[] args) throws IOException {
        int porto = args.length > 0 ? Integer.parseInt(args[0]) : PORTO_PREDEFINIDO;
        try (ServerSocket servidor = new ServerSocket(porto)) {
            System.out.println("Relay a escutar no porto " + porto);
            servir(servidor);
        }
    }
    // Separado do main para os testes poderem arrancar um relay num porto livre.
    public static void servir(ServerSocket servidor) throws IOException {
        while (true) {
            Socket socket = servidor.accept();
            new Thread(() -> atender(socket)).start(); // uma thread por cliente
        }
    }

    private static void atender(Socket socket) {
        String origem = socket.getRemoteSocketAddress().toString();
        System.out.println("Cliente ligado: " + origem);
        String meuNome = null; // fica preenchido depois de um REGISTO valido
        Ligacao lig = null;

        try (socket;
             DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            lig = new Ligacao(out);
            while (true) {
                Trama trama = Trama.ler(in);
                switch (trama.tipo) {
                    case Tipos.REGISTO -> registar(trama.corpo, lig);
                    case Tipos.PROCURAR -> procurar(trama.corpo, lig);
                    case Tipos.LEVANTAR -> pedirDesafio(trama.corpo, lig, meuNome);
                    case Tipos.RESPOSTA -> {
                        String nome = responderDesafio(trama.corpo, lig);
                        if (nome != null) {
                            meuNome = nome; // so agora a ligacao fica associada ao nome
                        }
                    }
                    case Tipos.ENVIAR -> {
                        if (meuNome == null) {
                            lig.erro("Tem de se autenticar primeiro (levantar)");
                        } else {
                            reencaminhar(meuNome, trama.corpo, lig);
                        }
                    }
                    default -> lig.erro("Tipo de trama desconhecido: " + trama.tipo);                                        
                }
            }
        } catch (IOException e) {
            // normal quando o cliente se desliga (ou envia uma trama mal formada)
        } finally {
            if (meuNome != null) {
                pendentes.desligar(meuNome, lig); // a partir daqui, as mensagens para ele sao guardadas
            }
            if (lig != null) {
                desafios.esquecer(lig); // um desafio por responder desta ligacao deixa de valer
            }            
            System.out.println("Cliente desligado: " + origem + (meuNome != null ? " (" + meuNome + ")" : ""));
        }
    }


    // O registo so publica as chaves publicas: NAO associa a ligacao ao nome.
    // A trama de registo nao tem nada de secreto e qualquer pessoa a podia repetir;
    // a ligacao so fica associada ao nome depois do desafio-resposta (modulo C).
    private static void registar(byte[] corpo, Ligacao lig) throws IOException {
        Registo novo;
        try {
            novo = Registo.ler(corpo); // valida o formato e verifica a assinatura
        } catch (Exception e) {
            lig.erro("Registo invalido: " + e.getMessage());
            return;
        }

        // Verificar-e-inserir numa so operacao atomica: evita que duas threads
        // registem o mesmo nome ao mesmo tempo com chaves diferentes.
        boolean[] recusado = {false};
        utilizadores.compute(novo.nome, (nome, atual) -> {
            if (atual != null && !Arrays.equals(atual.chaveAssinatura.getEncoded(),
                                                novo.chaveAssinatura.getEncoded())) {
                recusado[0] = true;
                return atual; // o nome continua a pertencer ao dono original
            }
            return novo;
        });
        if (recusado[0]) {
            lig.erro("Nome ja registado com outra chave");
            return;
        }

        System.out.println("Registado: " + novo.nome);
        lig.enviar(Tipos.REGISTO_OK, new byte[0]);
    }
    

    // modulo C: levantamento por desafio-resposta 
    
    private static void pedirDesafio(byte[] corpo, Ligacao lig, String autenticado) throws IOException {
        String nome = new String(corpo, StandardCharsets.UTF_8);
        if (autenticado != null && !autenticado.equals(nome)) {
            lig.erro("Esta ligacao ja esta autenticada como " + autenticado);
            return;
        }
        if (!utilizadores.containsKey(nome)) {
            lig.erro("Utilizador desconhecido: " + nome);
            return;
        }
        lig.enviar(Tipos.DESAFIO, desafios.novo(lig, nome));
    }

    // Devolve o nome autenticado, ou null se a resposta foi recusada.
    private static String responderDesafio(byte[] corpo, Ligacao lig) throws IOException {
        String nome;
        try {
            byte[][] r = Levantamento.lerResposta(corpo);
            nome = desafios.verificar(lig, r[0], r[1], utilizadores::get);
        } catch (IOException | GeneralSecurityException e) {
            desafios.esquecer(lig); // uma resposta mal formada tambem gasta o desafio
            System.out.println("Levantamento recusado: " + e.getMessage());
            lig.erro("Levantamento recusado: " + e.getMessage());
            return null;
        }
        // Provado quem e: entrega as pendentes e passa a receber as novas em direto.
        int entregues = pendentes.ligarEEntregar(nome, lig);
        System.out.println("Autenticado: " + nome + " (" + entregues + " pendentes entregues)");
        lig.enviar(Tipos.LEVANTAR_OK, ByteBuffer.allocate(4).putInt(entregues).array());
        return nome;
    }

    private static void procurar(byte[] corpo, Ligacao lig) throws IOException {
        String nome = new String(corpo, StandardCharsets.UTF_8);
        Registo r = utilizadores.get(nome);
        if (r == null) {
            lig.erro("Utilizador desconhecido: " + nome);
        } else {
            // Devolve os bytes originais assinados: o cliente verifica a assinatura sozinho.
            lig.enviar(Tipos.PROCURAR_RESP, r.bytes());
        }
    }

    // Corpo de ENVIAR: writeUTF(destinatario) | [len][envelope]
    private static void reencaminhar(String remetente, byte[] corpo, Ligacao lig) throws IOException {
        String destino;
        byte[] envelope;
        try {
            DataInputStream d = new DataInputStream(new ByteArrayInputStream(corpo));
            destino = d.readUTF();
            envelope = Bytes.ler(d, Trama.MAX_CORPO);
        } catch (IOException e) {
            lig.erro("Pedido de envio mal formado");
            return;
        }

        // So se guardam mensagens para utilizadores registados.
        if (!utilizadores.containsKey(destino)) {
            lig.erro("Utilizador desconhecido: " + destino);
            return;
        }

        // Ligado: entrega ja. Desligado: guarda (o relay nao consegue ler o envelope).
        switch (pendentes.entregarOuGuardar(destino, envelope)) {
            case ENTREGUE -> {
                System.out.println("Entregue " + remetente + " -> " + destino
                        + " (" + envelope.length + " bytes cifrados)");
                lig.enviar(Tipos.ENVIAR_OK, "entregue".getBytes(StandardCharsets.UTF_8));
            }
            case GUARDADA -> {
                System.out.println("Guardada " + remetente + " -> " + destino + " (" + envelope.length
                        + " bytes cifrados; " + pendentes.quantas(destino) + " pendentes)");
                lig.enviar(Tipos.ENVIAR_OK, "guardada".getBytes(StandardCharsets.UTF_8));
            }
            case CAIXA_CHEIA -> lig.erro("Caixa de " + destino + " cheia: mensagem recusada");
        }
        
    }
}
