package client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Identidade {
    private static final int ITERACOES_PBKDF2 = 210_000;
    private static final int TAMANHO_CHAVE_BITS = 256;
    private static final int TAMANHO_SALT_BYTES = 16;
    private static final int TAMANHO_IV_BYTES = 12;
    private static final int TAMANHO_TAG_GCM_BITS = 128;
    private static final byte[] MAGIC = new byte[] { 'E', 'I', 'A', '1' };

    private final String nome;
    private final KeyPair assinaturaEd25519;
    private final KeyPair acordoX25519;

    public Identidade(String nome, KeyPair assinaturaEd25519, KeyPair acordoX25519) {
        this.nome = nome;
        this.assinaturaEd25519 = assinaturaEd25519;
        this.acordoX25519 = acordoX25519;
    }

    public String getNome() {
        return nome;
    }

    public KeyPair getAssinaturaEd25519() {
        return assinaturaEd25519;
    }

    public KeyPair getAcordoX25519() {
        return acordoX25519;
    }

    public static Identidade carregarOuCriar(Path ficheiro, String nome, char[] palavraPasse) throws Exception {
        if (nome == null || nome.isBlank()) {
            throw new IllegalArgumentException("O nome do utilizador não pode estar vazio.");
        }
        if (palavraPasse == null || palavraPasse.length == 0) {
            throw new IllegalArgumentException("A palavra-passe não pode estar vazia.");
        }

        try {
            if (Files.exists(ficheiro)) {
                return carregar(ficheiro, nome, palavraPasse);
            }

            KeyPair ed25519 = gerarParChaves("Ed25519");
            KeyPair x25519 = gerarParChaves("X25519");
            Identidade identidade = new Identidade(nome, ed25519, x25519);
            guardar(ficheiro, identidade, palavraPasse);
            return identidade;
        } finally {
            Arrays.fill(palavraPasse, '\0');
        }
    }

    private static KeyPair gerarParChaves(String algoritmo) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algoritmo);
        return kpg.generateKeyPair();
    }

    private static SecretKey derivarChaveAes(char[] palavraPasse, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(palavraPasse, salt, ITERACOES_PBKDF2, TAMANHO_CHAVE_BITS);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] chaveDerivada = skf.generateSecret(spec).getEncoded();
        spec.clearPassword();
        try {
            return new SecretKeySpec(chaveDerivada, "AES");
        } finally {
            Arrays.fill(chaveDerivada, (byte) 0);
        }
    }

    private static byte[] serializarChaves(Identidade identidade) throws IOException {
        byte[] edPriv = identidade.assinaturaEd25519.getPrivate().getEncoded();
        byte[] edPub = identidade.assinaturaEd25519.getPublic().getEncoded();
        byte[] xPriv = identidade.acordoX25519.getPrivate().getEncoded();
        byte[] xPub = identidade.acordoX25519.getPublic().getEncoded();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(baos)) {
            escreverBloco(out, edPriv);
            escreverBloco(out, edPub);
            escreverBloco(out, xPriv);
            escreverBloco(out, xPub);
        } finally {
            Arrays.fill(edPriv, (byte) 0);
            Arrays.fill(xPriv, (byte) 0);
        }
        return baos.toByteArray();
    }

    private static Identidade desserializarChaves(String nome, byte[] emClaro) throws Exception {
        byte[] edPrivBytes;
        byte[] edPubBytes;
        byte[] xPrivBytes;
        byte[] xPubBytes;

        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(emClaro))) {
            edPrivBytes = lerBloco(in);
            edPubBytes = lerBloco(in);
            xPrivBytes = lerBloco(in);
            xPubBytes = lerBloco(in);
        }

        try {
            KeyPair ed25519 = reconstruirParChaves("Ed25519", edPrivBytes, edPubBytes);
            KeyPair x25519 = reconstruirParChaves("X25519", xPrivBytes, xPubBytes);
            return new Identidade(nome, ed25519, x25519);
        } finally {
            Arrays.fill(edPrivBytes, (byte) 0);
            Arrays.fill(xPrivBytes, (byte) 0);
        }
    }

    private static KeyPair reconstruirParChaves(String algoritmo, byte[] privEncoded, byte[] pubEncoded) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(algoritmo);
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(privEncoded));
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(pubEncoded));
        return new KeyPair(pub, priv);
    }

    private static void guardar(Path ficheiro, Identidade identidade, char[] palavraPasse) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[TAMANHO_SALT_BYTES];
        byte[] iv = new byte[TAMANHO_IV_BYTES];
        random.nextBytes(salt);
        random.nextBytes(iv);

        SecretKey chaveAes = derivarChaveAes(palavraPasse, salt);
        byte[] nomeBytes = identidade.nome.getBytes(StandardCharsets.UTF_8);
        byte[] emClaro = serializarChaves(identidade);

        byte[] cifrado;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAMANHO_TAG_GCM_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, chaveAes, gcmSpec);
            // Autentica também o cabeçalho/nome como AAD para impedir troca de ficheiro entre utilizadores
            cipher.updateAAD(MAGIC);
            cipher.updateAAD(salt);
            cipher.updateAAD(iv);
            cipher.updateAAD(nomeBytes);
            cifrado = cipher.doFinal(emClaro);
        } finally {
            Arrays.fill(emClaro, (byte) 0);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(baos)) {
            out.write(MAGIC);
            out.write(salt);
            out.write(iv);
            escreverBloco(out, nomeBytes);
            escreverBloco(out, cifrado);
        }

        Path pai = ficheiro.getParent();
        if (pai != null) {
            Files.createDirectories(pai);
        }
        Files.write(ficheiro, baos.toByteArray());
    }

    private static Identidade carregar(Path ficheiro, String nomeEsperado, char[] palavraPasse) throws Exception {
        byte[] dados = Files.readAllBytes(ficheiro);
        byte[] salt = new byte[TAMANHO_SALT_BYTES];
        byte[] iv = new byte[TAMANHO_IV_BYTES];
        byte[] nomeBytes;
        byte[] cifrado;

        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(dados))) {
            byte[] magicLido = new byte[MAGIC.length];
            in.readFully(magicLido);
            if (!Arrays.equals(MAGIC, magicLido)) {
                throw new IOException("Formato de ficheiro de identidade inválido.");
            }
            in.readFully(salt);
            in.readFully(iv);
            nomeBytes = lerBloco(in);
            cifrado = lerBloco(in);
        }

        String nomeGuardado = new String(nomeBytes, StandardCharsets.UTF_8);
        if (!nomeEsperado.equals(nomeGuardado)) {
            throw new SecurityException("O ficheiro de identidade não pertence ao utilizador '" + nomeEsperado + "'.");
        }

        SecretKey chaveAes = derivarChaveAes(palavraPasse, salt);
        byte[] emClaro;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAMANHO_TAG_GCM_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, chaveAes, gcmSpec);
            cipher.updateAAD(MAGIC);
            cipher.updateAAD(salt);
            cipher.updateAAD(iv);
            cipher.updateAAD(nomeBytes);
            emClaro = cipher.doFinal(cifrado);
        } catch (Exception e) {
            throw new SecurityException("Falha ao decifrar a identidade (palavra-passe incorreta ou ficheiro adulterado).", e);
        }

        return desserializarChaves(nomeGuardado, emClaro);
    }

    private static void escreverBloco(DataOutputStream out, byte[] bytes) throws IOException {
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static byte[] lerBloco(DataInputStream in) throws IOException {
        int tamanho = in.readInt();
        if (tamanho < 0 || tamanho > 1_000_000) {
            throw new IOException("Tamanho de bloco inválido no ficheiro de identidade: " + tamanho);
        }
        byte[] bloco = new byte[tamanho];
        in.readFully(bloco);
        return bloco;
    }
}