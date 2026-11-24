package client;

import common.Bytes;
import common.CadeiaChaves;
import common.Mensagem;
import common.Registo;
import common.Tipos;
import common.Trama;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;


//Threads:
//main: le comandos do teclado e faz pedidos ao relay (um de cada vez);
//leitora: le TODAS as tramas que chegam do relay. As respostas a pedidos
//vao para a fila 'respostas'; as mensagens recebidas (ENTREGA) vao para a
//thread 'trabalho', que as decifra (e pode precisar de pedir as chaves do
//remetente ao relay, por isso nao pode ser a propria leitora a faze-lo).

public class ClientMain {

    private static final DateTimeFormatter HORA =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final String nome;
    private final KeyPair parAssinatura; // Ed25519
    private final KeyPair parAcordo;     // X25519
    private final Contactos gestorContactos;
    private final DataOutputStream out;
    private final BlockingQueue<Trama> respostas = new LinkedBlockingQueue<>();
    private final ExecutorService trabalho = Executors.newSingleThreadExecutor();

    // Contactos ja obtidos nesta sessao (nome -> registo verificado).
    private final ConcurrentHashMap<String, Registo> contactos = new ConcurrentHashMap<>();

    // Cadeias do Ratchet por contacto (Modulo B).
    private final ConcurrentHashMap<String, CadeiaChaves> cadeiasEnvio = new ConcurrentHashMap<>();
    private final GestorCadeias cadeiasRececao; // uma cadeia por (remetente, sessao), guardada em ficheiro

    private ClientMain(Identidade identidade, Contactos gestorContactos, GestorCadeias cadeiasRececao,
                       DataOutputStream out) {
        this.nome = identidade.getNome();
        this.parAssinatura = identidade.getAssinaturaEd25519();
        this.parAcordo = identidade.getAcordoX25519();
        this.gestorContactos = gestorContactos;
        this.cadeiasRececao = cadeiasRececao;
        this.out = out;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Uso: java -cp out client.ClientMain <nome> [host] [porto]");
            return;
        }
        String nome = args[0];
        Registo.validarNome(nome);
        String host = args.length > 1 ? args[1] : "localhost";
        int porto = args.length > 2 ? Integer.parseInt(args[2]) : 5000;

        char[] palavraPasse = lerPalavraPasse(nome);
        Path ficheiroIdentidade = Path.of("dados", nome + ".id");
        Identidade identidade = Identidade.carregarOuCriar(ficheiroIdentidade, nome, palavraPasse);

        Path ficheiroContactos = Path.of("dados", nome + ".contactos");
        Contactos gestorContactos = Contactos.carregar(ficheiroContactos, identidade);

        Path ficheiroCadeias = Path.of("dados", nome + ".cadeias");
        GestorCadeias cadeiasRececao = GestorCadeias.carregar(ficheiroCadeias, identidade);

        try (Socket socket = new Socket(host, porto);
             DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            ClientMain cliente = new ClientMain(identidade, gestorContactos, cadeiasRececao, out);
            cliente.iniciarLeitora(in);
            if (cliente.registar()) {
                cliente.ciclo();
            }
            cliente.trabalho.shutdownNow();
            gestorContactos.destruir();
        }
    }

    private static char[] lerPalavraPasse(String nome) throws IOException {
        Console consola = System.console();
        if (consola != null) {
            char[] pass = consola.readPassword("Palavra-passe para '%s': ", nome);
            if (pass == null) {
                throw new IOException("Leitura de palavra-passe cancelada.");
            }
            return pass;
        }
        System.out.print("Palavra-passe para '" + nome + "': ");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String linha = br.readLine();
        if (linha == null) {
            throw new IOException("Leitura de palavra-passe cancelada.");
        }
        return linha.toCharArray();
    }

    // comunicacao com o relay

    private synchronized Trama pedido(byte tipo, byte[] corpo) throws IOException, InterruptedException {
        Trama.escrever(out, tipo, corpo);
        Trama resposta = respostas.poll(10, TimeUnit.SECONDS);
        if (resposta == null) {
            throw new IOException("Sem resposta do relay");
        }
        return resposta;
    }

    private void iniciarLeitora(DataInputStream in) {
        Thread leitora = new Thread(() -> {
            try {
                while (true) {
                    Trama t = Trama.ler(in);
                    if (t.tipo == Tipos.ENTREGA) {
                        trabalho.submit(() -> receber(t.corpo));
                    } else {
                        respostas.put(t);
                    }
                }
            } catch (IOException | InterruptedException e) {
                System.out.println("Ligacao ao relay terminada.");
                System.exit(0);
            }
        });
        leitora.setDaemon(true);
        leitora.start();
    }

    private boolean registar() throws Exception {
        byte[] corpo = Registo.criar(nome, parAssinatura, parAcordo);
        Trama r = pedido(Tipos.REGISTO, corpo);
        if (r.tipo == Tipos.REGISTO_OK) {
            System.out.println("Registado como '" + nome + "'.");
            System.out.println("Comandos: procurar <nome> | verificar <nome> | enviar <nome> <texto> | sair");
            return true;
        }
        System.out.println("Registo recusado: " + texto(r));
        return false;
    }

    // Descoberta: pede o registo ao relay, verifica assinatura e aplica politica TOFU.
    private Registo obterContacto(String outro) throws Exception {
        Registo conhecido = contactos.get(outro);
        if (conhecido != null) {
            return conhecido;
        }
        Trama r = pedido(Tipos.PROCURAR, outro.getBytes(StandardCharsets.UTF_8));
        if (r.tipo != Tipos.PROCURAR_RESP) {
            throw new IOException(texto(r));
        }
        Registo reg = Registo.ler(r.corpo);
        if (!reg.nome.equals(outro)) {
            throw new IOException("O relay devolveu o registo de outro utilizador");
        }

        boolean primeiraVez = gestorContactos.verificarOuRegistarTofu(reg);
        if (primeiraVez) {
            System.out.println("[TOFU] Contacto '" + outro + "' registado na primeira utilizacao. "
                    + "Usa 'verificar " + outro + "' para confirmar o codigo fora de banda.");
        }

        contactos.put(outro, reg);
        return reg;
    }

    private CadeiaChaves obterCadeiaEnvio(Registo destino) throws GeneralSecurityException {
        CadeiaChaves cadeia = cadeiasEnvio.get(destino.nome);
        if (cadeia == null) {
            cadeia = CadeiaChaves.criarParaEnvio(parAcordo.getPrivate(), destino.chaveAcordo, nome, destino.nome);
            cadeiasEnvio.put(destino.nome, cadeia);
        }
        return cadeia;
    }

    private CadeiaChaves obterCadeiaRececao(Registo remetente, long idSessao) throws GeneralSecurityException {
        return cadeiasRececao.obter(remetente, idSessao, parAcordo.getPrivate(), nome);
    }

    private void enviar(String destino, String texto) throws Exception {
        Registo reg = obterContacto(destino);
        CadeiaChaves cadeia = obterCadeiaEnvio(reg);
        byte[] envelope = Mensagem.selar(nome, parAssinatura, cadeia, reg, texto);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(buffer);
        d.writeUTF(destino);
        Bytes.escrever(d, envelope);

        Trama r = pedido(Tipos.ENVIAR, buffer.toByteArray());
        if (r.tipo == Tipos.ENVIAR_OK) {
            System.out.println("[" + texto(r) + " para " + destino + "]");
        } else {
            System.out.println("Nao enviada: " + texto(r));
        }
    }

    // Corre na thread 'trabalho'.
    private void receber(byte[] envelope) {
        try {
            Mensagem m = Mensagem.ler(envelope);
            Registo reg = obterContacto(m.remetente);
            CadeiaChaves cadeia = obterCadeiaRececao(reg, m.idSessao);
            String texto;
            try {
                texto = m.abrir(nome, cadeia, reg);
            } finally {
                cadeiasRececao.guardar(); // o estado avancou: grava-o para sobreviver a reinicios
            }
            System.out.println("[" + HORA.format(Instant.ofEpochMilli(m.instante)) + "] "
                    + m.remetente + ": " + texto);
        } catch (Exception e) {
            System.out.println("!! Mensagem rejeitada: " + e.getMessage());
        }
    }

    // ---------- interface de texto ----------

    private void ciclo() throws IOException {
        // Modulo C (A3): antes de tudo, provar ao relay quem somos e levantar as mensagens guardadas.
        // Sem isto o relay nao entrega mensagens a esta ligacao nem aceita ENVIAR.
        try {
            levantar();
        } catch (Exception e) {
            System.out.println("Levantamento recusado: " + e.getMessage());
            return;
        }
        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String linha;
        while ((linha = teclado.readLine()) != null) {
            String[] partes = linha.trim().split(" ", 3);
            try {
                switch (partes[0]) {
                    case "procurar" -> {
                        if (partes.length < 2) { System.out.println("Uso: procurar <nome>"); break; }
                        Registo reg = obterContacto(partes[1]);
                        System.out.println(reg.nome + " encontrado (registo com assinatura valida).");
                    }
                    case "verificar" -> {
                        if (partes.length < 2) { System.out.println("Uso: verificar <nome>"); break; }
                        Registo reg = obterContacto(partes[1]);
                        String codigo = gestorContactos.obterCodigoVerificacao(reg.nome);
                        System.out.println("Codigo de verificacao de '" + reg.nome + "': " + codigo);
                    }
                    case "enviar" -> {
                        if (partes.length < 3) { System.out.println("Uso: enviar <nome> <texto>"); break; }
                        enviar(partes[1], partes[2]);
                    }
                    case "levantar" -> levantar(); // modulo C (A3)                    
                    case "sair" -> { return; }
                    case "" -> { }
                    default -> System.out.println("Comandos: procurar <nome> | verificar <nome> | enviar <nome> <texto> | sair");
                }
            } catch (Exception e) {
                System.out.println("Erro: " + e.getMessage());
            }
        }
    }

    // Modulo C (A3): desafio-resposta com o relay e levantamento das mensagens pendentes.
    private void levantar() throws Exception {
        int n = Levantar.executar(this::pedido, nome, parAssinatura.getPrivate());
        System.out.println("Autenticado no relay. Mensagens pendentes levantadas: " + n);
    }

    private static String texto(Trama t) {
        return new String(t.corpo, StandardCharsets.UTF_8);
    }
}