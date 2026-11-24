# EIA_SI — Mensageiro Seguro

Trabalho prático da UC de Segurança Informática (Grupo 4: António Sacchetti e Pedro Almeida).

Sistema de mensagens seguras em Java, só com bibliotecas do JDK: um **relay** que encaminha e guarda mensagens cifradas, e **clientes** que trocam mensagens cifradas de ponta a ponta.

Módulos do grupo:
- **A** — TOFU e verificação de impressões digitais (comandos `verificar` e `meucodigo`)
- **B** — cadeia de chaves simétrica (ratchet com HKDF)
- **C** — levantamento de mensagens por desafio-resposta

Requisitos: JDK 15 ou superior (desenvolvido com o OpenJDK 25.0.1).

---

## Passo 1 — Abrir o terminal na pasta do projeto

Todos os comandos são escritos na raiz do projeto (a pasta que tem `src` e este README).

## Passo 2 — Compilar

macOS / Linux:
```
rm -rf out
javac -d out $(find src -name "*.java")
```

Windows (PowerShell):
```
javac -d out (Get-ChildItem -Recurse src -Filter *.java).FullName
```

Se não aparecer nenhuma mensagem, a compilação correu bem. É criada a pasta `out` com as classes compiladas.

## Passo 3 — Correr os testes (opcional)

Um teste:
```
java -cp out teste.TesteRatchet
```

Todos os testes (macOS / Linux):
```
for t in $(ls src/teste | sed 's/.java//'); do echo "=== $t"; java -cp out teste.$t 2>&1 | tail -3; done
```

Todos os testes (Windows, PowerShell):
```
Get-ChildItem src/teste -Filter *.java | ForEach-Object { "=== " + $_.BaseName; java -cp out ("teste." + $_.BaseName) }
```

Cada teste termina com uma linha `OK - ... passou.` ou `Todos os testes passaram.`. As linhas `Cliente ligado` e `Cliente desligado` que aparecem a meio são do relay que alguns testes arrancam, e não são erros.

| Teste | O que verifica |
|---|---|
| `TesteTrama`, `TesteChaves` | Formato das tramas; assinaturas Ed25519 e acordo X25519 |
| `TesteHkdf` | HKDF com os vetores de teste da RFC 5869 |
| `TesteMensagem` | Envelope cifrado, alterações detetadas, remetente falsificado rejeitado |
| `TesteRatchet`, `TesteGestorCadeias` | Módulo B: chave por mensagem, fora de ordem, repetições, estado guardado em disco |
| `TesteIdentidade` | Ficheiro de identidade cifrado com a palavra-passe |
| `TesteContactos`, `TesteCodigoVerificacao` | Módulo A: TOFU, HMAC dos contactos, código de verificação |
| `TesteRegisto` | Nome ocupado e registo adulterado recusados |
| `TesteArmazenamento`, `TestePendentes` | Armazenamento diferido no relay |
| `TesteDesafios`, `TesteLevantamento` | Módulo C: desafio-resposta |
| `TesteRobustez` | Tempos limite e limite de ligações do relay |

## Passo 4 — Arrancar o relay (terminal 1)

```
java -cp out relay.RelayMain
```
Deve aparecer:
```
Relay a escutar no porto 5000
```
O terminal fica ocupado com o relay a correr. Não o feche.

## Passo 5 — Arrancar o cliente "bruno" (terminal 2)

Abra um **segundo terminal** (no VS Code, o **+** no canto superior direito do painel do terminal) e escreva:
```
java -cp out client.ClientMain bruno
```
O cliente pede uma palavra-passe. Na primeira vez, escolha uma nova: é ela que protege as chaves do bruno, guardadas em `dados/bruno.id`. Nas vezes seguintes, use a mesma.

Deve aparecer:
```
Registado como 'bruno'.
Comandos: procurar <nome> | verificar <nome> | meucodigo | enviar <nome> <texto> | levantar | sair
Autenticado no relay. Mensagens pendentes levantadas: 0
```
A linha `Autenticado no relay` é o desafio-resposta (módulo C): o cliente provou ao relay que tem a chave privada do bruno.

## Passo 6 — Arrancar o cliente "ana" (terminal 3)

Abra um **terceiro terminal** e escreva:
```
java -cp out client.ClientMain ana
```
Escolha também uma palavra-passe. Deve aparecer o mesmo que no Passo 5, com `ana`.

## Passo 7 — Enviar uma mensagem

No terminal da **ana**:
```
procurar bruno
enviar bruno ola, tudo bem?
```

| Terminal | O que deve aparecer |
|---|---|
| ana | `[TOFU] Contacto 'bruno' registado na primeira utilizacao...`, `bruno encontrado (registo com assinatura valida).` e `[entregue para bruno]` |
| bruno | `[hh:mm:ss] ana: ola, tudo bem?` |
| relay | `Entregue ana -> bruno (... bytes cifrados)` |

O relay só mostra o tamanho da mensagem e nunca o texto, porque a mensagem vai cifrada de ponta a ponta.

## Passo 8 — Confirmar a identidade por telefone (módulo A)

- No terminal da **ana**: `verificar bruno` mostra o código do bruno, por exemplo `5114-0999-4372`.
- No terminal do **bruno**: `meucodigo` mostra o código dele.

Os dois códigos têm de ser iguais. Na vida real, a ana e o bruno comparavam-nos por telefone: se forem diferentes, alguém trocou a chave pelo caminho.

## Passo 9 — Mensagem com o destinatário desligado (armazenamento diferido e módulo C)

1. No terminal do **bruno**, escreva `sair`.
2. No terminal da **ana**: `enviar bruno estas ai?` deve responder `[guardada para bruno]`.
3. Volte a arrancar o bruno: `java -cp out client.ClientMain bruno` (com a mesma palavra-passe).

Deve aparecer `Autenticado no relay. Mensagens pendentes levantadas: 1`, seguido da mensagem da ana. O relay só entregou a mensagem depois de o bruno responder ao desafio.

## Passo 10 — Terminar

- Nos clientes, escreva `sair`.
- No relay, carregue `Ctrl+C`.

---

## Notas

- Cada cliente guarda os seus ficheiros na pasta `dados/` (identidade, contactos e estado das cadeias, todos protegidos). Esta pasta está no `.gitignore` e não deve ir para o repositório.
- Para recomeçar do zero, pare o relay e os clientes e apague a pasta `dados/`. Se apagar só os ficheiros de um utilizador com o relay a correr, o relay recusa o nome, porque ele continua registado com a chave antiga.
- Opções: `java -cp out relay.RelayMain <porto>` e `java -cp out client.ClientMain <nome> <host> <porto>`.
