# Intrusion Detection System

IDS híbrido de rede e host: captura pacotes com Scapy, normaliza tudo em eventos,
avalia regras de detecção sobre eles, correlaciona os achados por origem e entrega
alertas com evidência num dashboard ao vivo, numa API REST e em SQLite.

É estritamente defensivo. O sistema observa e relata — não envia pacote nenhum, não
faz varredura ativa, não bloqueia host, não derruba conexão e não executa nada no
alvo monitorado.

Python 3.12 · Scapy · Flask · SQLite · Server-Sent Events · Textual

## Finalidade

Dar visibilidade sobre o que acontece numa rede e nos hosts dela sem depender de um
SIEM: identificar varredura de portas, picos anômalos de volume e tentativas repetidas
de autenticação, explicando cada alerta com a evidência que o produziu, a severidade,
a confiança e o que fazer a respeito.

O foco é qualidade de detecção, não quantidade: cada regra existe junto com o motivo
pelo qual ela não dispara, porque um IDS que grita a cada pacote é um IDS que ninguém
lê.

## Como funciona

```text
                        ┌── captura (Scapy, thread própria)
pacote ─────────────────┤
                        └── simulador (pacotes em memória, sem rede)
                                 │
                                 ▼
                        fila limitada (backpressure)
                                 │
                                 ▼
   parser ──> evento normalizado ──> regras ──> correlação ──> alert manager
                     ▲                                              │
   log de host ──────┘                                   ┌──────────┴──────────┐
                                                         ▼                     ▼
                                                      SQLite            barramento
                                                         │                     │
                                                         └──> API REST ──> dashboard
```

- **Uma fila, uma thread de regras** — o callback do Scapy só enfileira; parsing,
  detecção e alerta rodam noutra thread. Eventos de host entram pela mesma fila, então
  o estado das regras é tocado por uma thread só e dispensa lock
- **Backpressure explícito** — a fila é limitada. Cheia, descarta o pacote mais novo e
  incrementa `packets_dropped`: bloquear a captura empurraria a perda para o kernel,
  onde não dá para contá-la, e uma fila infinita trocaria perda por OOM
- **Estado sempre limitado** — toda regra temporal expira por tempo *e* tem teto de
  chaves rastreadas, com remoção da mais antiga. Estado que cresce sem limite é como um
  IDS morre depois de uma semana no ar
- **Isolamento de falhas** — uma regra que lança exceção é contada, logada com
  traceback e ignorada; captura, API e as outras regras seguem
- **Severidade e confiança separadas** — "quão grave se for real" e "quão certo estou"
  são perguntas diferentes, e todo alerta responde as duas
- **Só metadados** — o parser extrai endereços, portas, flags e tamanho. Payload nunca
  é armazenado

| Regra | Detecta | Severidade | MITRE |
|---|---|---|---|
| `port_scan` | Conexões a muitas portas distintas | MEDIUM / HIGH | T1046 |
| `traffic_anomaly` | Volume acima da baseline recente | MEDIUM | — |
| `brute_force` | Falhas de autenticação repetidas | MEDIUM | T1110 |
| `correlation` | Tipos diferentes na mesma origem | herdada | — |

Nenhuma afirma ter visto um ataque:

- **`port_scan`** — conta só SYN sem ACK, que é tentativa de conexão; um servidor
  ocupado falando em portas efêmeras não parece scanner. Agrega por janela e tem
  cooldown: mil portas viram um ou dois alertas, não mil
- **`traffic_anomaly`** — não é "detector de DDoS". Pico de volume é afirmação sobre
  tráfego, não sobre intenção: backup, deploy e enchente são idênticos num contador de
  pacotes. Sai com confiança LOW e exige baseline cheia e um piso mínimo de pacotes
- **`brute_force`** — lê falhas que **já aconteceram**, vindas de log. Distingue ataque
  a uma conta de spraying entre várias, e um login bem-sucedido no meio não zera o
  contador
- **`correlation`** — agrupa, não escala: a severidade é a maior entre os componentes.
  Três sinais fracos não somam um forte

Sem MITRE onde não tenho certeza do ID: um pico de volume não é necessariamente
negação de serviço, então fica sem técnica associada em vez de receber uma inventada.

## Como rodar

Requer Python 3.12+:

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

A demonstração completa não precisa de privilégio nem de interface de rede — o
simulador constrói os pacotes em memória e os empurra pelo pipeline real:

```sh
.venv/bin/python -m ids simulate --scenario all --serve
# dashboard em http://127.0.0.1:8080
```

Captura de verdade exige privilégio (veja abaixo):

```sh
.venv/bin/python -m ids check                      # o que falta para capturar
.venv/bin/python -m ids start --interface eth0 --auth-log /var/log/auth.log
```

| Comando | Função |
|---|---|
| `ids start` | Captura tráfego, monitora logs e serve o dashboard |
| `ids simulate --scenario <nome>` | Roda um cenário sintético pelo pipeline inteiro |
| `ids check` | Relata privilégios de captura, banco e regras carregadas |

Cenários: `normal`, `port_scan`, `traffic_burst`, `brute_force`, `correlated`, `all`.

Opções principais: `--interface`, `--bpf-filter`, `--auth-log`, `--database`,
`--config`, `--host`, `--port`, `--log-level`, `--no-dashboard`, `--no-capture`,
`--retention-days`. Configuração completa em `examples/config.toml`; precedência é
flag > variável `IDS_*` > arquivo TOML > padrão.

### Privilégios de captura

O programa **nunca** eleva privilégio sozinho, não chama `sudo` e não instala helper
setuid. Ele só relata o que falta:

- **Linux** — a opção mais estreita é dar as capabilities ao interpretador em vez de
  rodar tudo como root:
  `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)`
- **Windows** — instale o Npcap em modo compatível com WinPcap e rode o terminal como
  Administrador
- **macOS** — é preciso acesso de leitura a `/dev/bpf*`

## API

Todas as respostas usam o mesmo envelope `{"data": ..., "meta": {...}}`, e todo
parâmetro é validado antes de chegar ao banco — valor inválido vira 400, nunca um
palpite.

| Endpoint | Retorna |
|---|---|
| `GET /api/alerts` | Alertas paginados e filtrados |
| `GET /api/alerts/<id>` | Um alerta com evidência e remediação |
| `GET /api/stats` | Totais, contagem por severidade e origens mais ruidosas |
| `GET /api/metrics` | Contadores do pipeline, gauges e tamanho do estado por regra |
| `GET /api/traffic` | Janelas de tráfego fechadas, com taxas |
| `GET /api/events` | Eventos normalizados recentes |
| `GET /api/health` | Estado de banco, captura, fila e detectores |
| `GET /api/stream` | Alertas ao vivo por Server-Sent Events |

Filtros de `/api/alerts`: `severity`, `min_severity`, `source_ip`, `detection_type`,
`start_time`, `end_time`, `limit` e `offset`.

Tempo real é SSE, não WebSocket: o tráfego é de mão única (servidor para navegador),
`EventSource` reconecta sozinho, anda sobre o HTTP que já está servido e não custa
dependência nenhuma. Um WebSocket acrescentaria biblioteca e protocolo para ganhar um
canal de volta que este dashboard não usa. O dashboard cai para polling se o stream
falhar.

## Console no terminal

O dashboard web serve bem quem tem navegador. Quem está **na máquina** — via SSH,
sem browser e sem porta para expor — quer a mesma coisa no terminal. O bind padrão
é `127.0.0.1` justamente porque alcançá-lo de outra máquina exige um proxy com
autenticação e TLS; um console não exige nada disso.

Um arquivo executável prepara o ambiente e abre o console:

```sh
./launch-tui                              # só o pipeline, sem privilégio nenhum
./launch-tui --capture --interface eth0   # captura de verdade
./launch-tui --scenario port_scan         # escolhe o que o botão FEED dispara
```

Ele cria `.venv` no repositório, instala o pacote com o extra `tui` e entrega o
controle. Não usa `sudo`, não instala pacote de sistema e **nunca concede
capabilities por você** — `ids check` continua sendo quem diz o que falta. Quem já
tem o ambiente pronto chama direto:

```sh
.venv/bin/pip install -e ".[tui]"
.venv/bin/ids-console --scenario all
```

| Aba | Mostra |
|---|---|
| Alert | Evidência, remediação, MITRE e ocorrências do alerta selecionado |
| Pipeline | Fila contra capacidade, pacotes descartados, contadores e health |
| Rules | Cada estágio com estado, o que reporta e quantas chaves está rastreando |
| Traffic | Sparkline de pacotes/s e as janelas fechadas recentes |
| Log | O stream de log do motor, ao vivo |

| Tecla | Ação |
|---|---|
| `ctrl+f` | Roda o cenário selecionado pelo pipeline real |
| `ctrl+l` | Limpa a tabela (não apaga nada do banco) |
| `ctrl+q` | Sai, parando o motor |

### Um segundo consumidor, não uma segunda opinião

O console assina o **mesmo `EventBus`** que o dashboard assina, lê os **mesmos**
contadores e os **mesmos** repositórios. Nenhum dos dois recalcula veredito: se
discordarem, é bug de renderização, não duas opiniões.

Isso é seguro porque o bus entrega em caixas postais limitadas por assinante. Um
console que fica para trás descarta as próprias mensagens e conta quantas — ele não
consegue atrasar o dashboard nem crescer fila até o processo morrer. Quando isso
acontece, a aba Pipeline diz exatamente isso, e que os alertas continuam no banco.

O nível de ameaça é derivado igual ao do dashboard: **a maior severidade presente**,
como nível e não como score. Um número composto a partir de quatro regras heurísticas
sugeriria uma precisão que nenhuma delas tem.

### O que o console se recusa a insinuar

- **`packets_dropped` fica ao lado da fila, não escondido num contador.** Pacote
  descartado é pacote que ninguém analisou; enquanto esse número sobe, lista de
  alertas vazia não é evidência de rede quieta — e o painel diz isso por escrito
- **NOMINAL não é "está tudo bem".** Significa que nada disparou, o que não é uma
  afirmação sobre o que aconteceu
- **Todo alerta termina dizendo que é indicador, não ataque confirmado**
- **Limpar a tabela não apaga nada.** O texto que fica no lugar diz onde os alertas
  continuam

## Testes

```sh
.venv/bin/pytest                    # 234 testes: unitários, integração e API
.venv/bin/pytest --cov=ids          # com cobertura
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

A suíte não toca em rede: os pacotes são construídos com Scapy em memória, então roda
sem privilégio e sem interface. Os testes de integração exercitam o pipeline real —
captura, parser, regras, alertas e SQLite — e os casos negativos são tão explícitos
quanto os positivos: tráfego benigno não pode gerar alerta, cinquenta conexões à mesma
porta não são varredura, e uma varredura distribuída entre origens é falso negativo
declarado.

O console é exercitado pelo piloto headless do Textual contra um motor de verdade —
o cenário passa pela fila, pelo parser, pelas regras, pela correlação, pelo SQLite e
pelo bus, não por um dublê deles. Há também um teste que confere a **geometria** de
cada controle em quatro larguras de terminal, de 80 colunas para cima: um widget
posicionado além da borda continua no DOM, uma query o encontra, e um teste que só
consulta passa enquanto o operador não enxerga o botão.

A CI roda a suíte em Python 3.12 e 3.13 mais `ruff` a cada push e pull request, e um
job separado constrói o wheel, instala num ambiente limpo e roda a suíte com a árvore
de fontes fora do `sys.path` — este projeto empacota três arquivos que não são código
(o template do dashboard, o CSS/JS e a folha de estilo do console), e nenhum teste
comum notaria a falta deles.

## Limitações

- **Sem autenticação na API e no dashboard** — por isso o bind padrão é `127.0.0.1`.
  Expor para outra máquina exige autenticação e TLS num proxy à frente. O servidor HTTP
  é de desenvolvimento (`wsgiref`), adequado a um operador na própria máquina, não a um
  serviço público
- **Falsos positivos previsíveis** — scanner de vulnerabilidade autorizado, monitoração,
  health check, balanceador, atualização de software e gateway NAT produzem exatamente
  os padrões que as regras procuram
- **Falsos negativos previsíveis** — varredura distribuída entre origens, ataque
  low-and-slow espalhado além da janela, tráfego cifrado, qualquer coisa fora da
  interface monitorada e autenticação atacada por caminhos que não geram log
- **Tráfego cifrado é opaco** — a análise é de metadados; conteúdo de sessão TLS não é
  inspecionado, e não há intenção de inspecioná-lo
- **Pacote perdido é pacote não analisado** — sob saturação a fila descarta, e o
  contador `packets_dropped` diz quanto. Um número alto invalida a ausência de alertas
- **Detecção baseada em regra e limiar** — sem aprendizado de máquina, sem assinaturas
  de terceiros, sem reconstrução de fluxo TCP

## Uso autorizado

Ferramenta defensiva de monitoramento. Use apenas em redes, sistemas e dispositivos que
você opera ou nos quais tem autorização explícita para monitorar. Capturar tráfego de
rede alheia costuma ser ilegal e frequentemente expõe dados de terceiros.

Por construção não há aqui exploração, varredura ativa, força bruta, envio de pacote,
bloqueio de host, encerramento de conexão, execução remota, coleta de credencial,
exfiltração, MITM, spoofing de ARP ou DNS, nem persistência em sistema monitorado.

## Licença

MIT — ver `LICENSE`.
