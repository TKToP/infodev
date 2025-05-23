const quizData = [
    // FÁCEIS
    {
question: "Qual das alternativas abaixo representa uma ameaça à segurança da informação?",
options: ["Atualizações de software", "Firewall ativo", "Vírus de computador", "Backup regular"],
answer: "Vírus de computador",
difficulty: "Fácil"
},
{
question: "O que é um firewall?",
options: ["Um antivírus", "Um software de edição de texto", "Uma barreira de proteção entre redes", "Um tipo de hardware de armazenamento"],
answer: "Uma barreira de proteção entre redes",
difficulty: "Fácil"
},
{
question: "O que significa a sigla 'VPN'?",
options: ["Virtual Public Network", "Very Private Network", "Virtual Private Network", "Verified Personal Network"],
answer: "Virtual Private Network",
difficulty: "Fácil"
},
{
question: "Qual destas práticas é uma boa medida de segurança?",
options: ["Usar senhas fracas", "Compartilhar login com colegas", "Deixar o computador desbloqueado", "Atualizar regularmente os sistemas"],
answer: "Atualizar regularmente os sistemas",
difficulty: "Fácil"
},
// MÉDIAS
{
question: "O que é autenticação de dois fatores (2FA)?",
options: ["Uma senha duplicada", "Uso de biometria", "Confirmação via dois métodos distintos", "Acesso por Wi-Fi seguro"],
answer: "Confirmação via dois métodos distintos",
difficulty: "Médio"
},
{
question: "Qual é a função principal da criptografia?",
options: ["Organizar os arquivos", "Compactar dados", "Proteger informações durante a transmissão", "Aumentar a velocidade da rede"],
answer: "Proteger informações durante a transmissão",
difficulty: "Médio"
},
{
question: "O que é um ataque de negação de serviço (DoS)?",
options: ["Roubo de dados por rede local", "Exclusão de backups", "Interrupção de serviços tornando-os inacessíveis", "Invasão de sistema com privilégio de root"],
answer: "Interrupção de serviços tornando-os inacessíveis",
difficulty: "Médio"
},
{
question: "Qual é o objetivo da política de segurança da informação em uma organização?",
options: ["Reduzir o número de funcionários", "Controlar o uso de internet", "Orientar sobre práticas seguras de uso de informação", "Limitar acessos físicos ao prédio"],
answer: "Orientar sobre práticas seguras de uso de informação",
difficulty: "Médio"
},

// DIFÍCEIS
{
question: "O que é um ataque de dia zero (zero-day)?",
options: ["Um vírus ativado na primeira hora do dia", "Um ataque que ocorre no primeiro dia útil do mês", "Exploração de uma vulnerabilidade desconhecida pelo fabricante", "Um ataque que depende de falha humana"],
answer: "Exploração de uma vulnerabilidade desconhecida pelo fabricante",
difficulty: "Difícil"
},
{
question: "O que caracteriza um ransomware?",
options: ["Roubo de identidade", "Destruição física de hardware", "Sequestro de dados mediante pagamento", "Interrupção temporária de energia"],
answer: "Sequestro de dados mediante pagamento",
difficulty: "Difícil"
},
{
question: "O que é uma sandbox no contexto de segurança da informação?",
options: ["Um firewall alternativo", "Uma área de testes isolada para execução segura de códigos", "Um antivírus de código aberto", "Um dispositivo de autenticação multifatorial"],
answer: "Uma área de testes isolada para execução segura de códigos",
difficulty: "Difícil"
},
{
question: "Em que situação uma chave assimétrica é mais indicada que uma simétrica?",
options: ["Quando se precisa de maior velocidade", "Quando ambos os lados compartilham a mesma chave", "Quando se deseja garantir confidencialidade sem troca prévia de chaves", "Quando o canal é seguro"],
answer: "Quando se deseja garantir confidencialidade sem troca prévia de chaves",
difficulty: "Difícil"
},
{
question: "Qual desses protocolos garante criptografia ponta a ponta na navegação web?",
options: ["HTTP", "FTP", "SMTP", "HTTPS"],
answer: "HTTPS",
difficulty: "Difícil"
},
{
question: "O que caracteriza um ataque Man-in-the-Middle (MitM)?",
options: ["Interceptação de comunicação entre duas partes sem que elas saibam", "Invasão por força bruta", "Desligamento remoto de servidores", "Troca de arquivos em nuvem sem permissão"],
answer: "Interceptação de comunicação entre duas partes sem que elas saibam",
difficulty: "Difícil"
},
{
question: "Qual a melhor definição para 'hash' em segurança da informação?",
options: ["Chave de acesso", "Função de compressão", "Função criptográfica que gera um resumo único de dados", "Número de série de rede"],
answer: "Função criptográfica que gera um resumo único de dados",
difficulty: "Difícil"

//MISTAS (FÁCIL, MÉDIO E DIFÍCIL)

},
{
question: "O que é um certificado digital?",
options: ["Um antivírus premium", "Um comprovante físico de segurança", "Um documento que garante identidade eletrônica", "Uma atualização de segurança"],
answer: "Um documento que garante identidade eletrônica",
difficulty: "Médio"
},
{
question: "Qual é a diferença entre malware e spyware?",
options: ["Spyware não existe mais", "Malware é apenas vírus, spyware é proteção", "Spyware é um tipo de malware voltado à espionagem", "Spyware é físico, malware é digital"],
answer: "Spyware é um tipo de malware voltado à espionagem",
difficulty: "Médio"
},
{
    question: "Qual destes é um exemplo de autenticação de dois fatores (2FA)?",
    options: ["Senha e login", "Senha e código enviado por SMS", "Login e pergunta secreta", "Senha simples"],
    answer: "Senha e código enviado por SMS",
    difficulty: "Fácil"
  },
  {
    question: "Qual é a função de um firewall?",
    options: ["Melhorar a velocidade da internet", "Impedir o acesso não autorizado à rede", "Criar backups automáticos", "Armazenar senhas"],
    answer: "Impedir o acesso não autorizado à rede",
    difficulty: "Fácil"
  },
  {
    question: "O que caracteriza um ataque de força bruta?",
    options: ["Uso de senha fraca", "Exploração de uma falha de software", "Tentativas repetidas de senha até acertar", "Acesso físico ao computador"],
    answer: "Tentativas repetidas de senha até acertar",
    difficulty: "Médio"
  },
  {
    question: "Qual das alternativas representa uma vulnerabilidade?",
    options: ["Sistema com atualizações frequentes", "Senha complexa", "Sistema desatualizado", "Autenticação multifator"],
    answer: "Sistema desatualizado",
    difficulty: "Médio"
  },
  {
    question: "O que é um ransomware?",
    options: ["Software de segurança", "Ataque que bloqueia dados e exige resgate", "Ferramenta de backup", "Vírus inofensivo"],
    answer: "Ataque que bloqueia dados e exige resgate",
    difficulty: "Médio"
  },
  {
    question: "Qual o objetivo principal da criptografia?",
    options: ["Reduzir tamanho de arquivos", "Tornar dados acessíveis a todos", "Proteger a confidencialidade das informações", "Facilitar o backup"],
    answer: "Proteger a confidencialidade das informações",
    difficulty: "Fácil"
  },
  {
    question: "Qual o nome do tipo de malware que se disfarça de software legítimo?",
    options: ["Trojan", "Worm", "Spyware", "Rootkit"],
    answer: "Trojan",
    difficulty: "Médio"
  },
  {
    question: "Qual a melhor prática ao criar uma senha segura?",
    options: ["Usar apenas letras", "Reutilizar senhas antigas", "Combinar letras, números e símbolos", "Nome de familiares"],
    answer: "Combinar letras, números e símbolos",
    difficulty: "Fácil"
  },
  {
    question: "Por que é importante atualizar softwares regularmente?",
    options: ["Melhorar design", "Aumentar o espaço de armazenamento", "Corrigir vulnerabilidades", "Melhorar compatibilidade com jogos"],
    answer: "Corrigir vulnerabilidades",
    difficulty: "Fácil"
  },
  {
    question: "Qual tipo de malware registra as teclas digitadas no teclado?",
    options: ["Ransomware", "Worm", "Keylogger", "Rootkit"],
    answer: "Keylogger",
    difficulty: "Médio"
  },
  {
    question: "Qual destes NÃO é um bom exemplo de boas práticas de segurança?",
    options: ["Usar autenticação de dois fatores", "Clicar em links de e-mails desconhecidos", "Atualizar o antivírus", "Fazer backup regularmente"],
    answer: "Clicar em links de e-mails desconhecidos",
    difficulty: "Fácil"
  },
  {
    question: "O que é o princípio da integridade na segurança da informação?",
    options: ["Garantir que as informações estejam disponíveis", "Evitar acessos não autorizados", "Assegurar que a informação não seja alterada sem autorização", "Manter os dados públicos"],
    answer: "Assegurar que a informação não seja alterada sem autorização",
    difficulty: "Fácil"
  },
  {
    question: "Como identificar um site seguro para realizar compras online?",
    options: ["Possui cores chamativas", "Termina com '.com'", "Utiliza HTTPS e cadeado na barra de endereços", "Oferece muitos anúncios"],
    answer: "Utiliza HTTPS e cadeado na barra de endereços",
    difficulty: "Fácil"
  },
  {
    question: "Qual desses conceitos está relacionado à disponibilidade?",
    options: ["Criptografia de dados", "Backups frequentes e redundância", "Controle de acesso", "Autenticação biométrica"],
    answer: "Backups frequentes e redundância",
    difficulty: "Médio"
  },
  {
    question: "O que caracteriza uma vulnerabilidade na infraestrutura?",
    options: ["Dependente da tecnologia", "Vulnerabilidades da infraestrutura", "Pouca atenção à segurança inicial", "Todas as alternativas estão corretas"],
    answer: "Vulnerabilidades da infraestrutura",
    difficulty: "Médio"
  },
  {
    question: "O que é spoofing?",
    options: ["Proteção por firewall", "Falsificação de identidade digital", "Monitoramento de rede", "Bloqueio de portas não utilizadas"],
    answer: "Falsificação de identidade digital",
    difficulty: "Difícil"
  },
  {
    question: "O que é um ataque de negação de serviço (DoS)?",
    options: [
        "Um ataque que visa roubar dados de um servidor",
        "Um ataque que visa impedir o acesso a um serviço",
        "Um vírus que se replica automaticamente",
        "Uma tentativa de se passar por outra pessoa"
    ],
    answer: "Um ataque que visa impedir o acesso a um serviço",
    difficulty: "Fácil"
},
{
    question: "O que é uma política de segurança da informação?",
    options: [
        "Um documento que orienta o uso de redes sociais",
        "Uma diretriz para seleção de senhas",
        "Um conjunto de diretrizes para proteger ativos de informação",
        "Um plano de marketing digital"
    ],
    answer: "Um conjunto de diretrizes para proteger ativos de informação",
    difficulty: "Fácil"
},
{
    question: "O que é um exploit?",
    options: [
        "Um software de backup",
        "Uma falha de hardware",
        "Um código que explora vulnerabilidades",
        "Uma técnica de criptografia"
    ],
    answer: "Um código que explora vulnerabilidades",
    difficulty: "Médio"
},
{
    question: "Qual das opções representa um risco interno à segurança da informação?",
    options: [
        "Ataque DDoS",
        "Funcionário desatento",
        "Malware externo",
        "Phishing de outro país"
    ],
    answer: "Funcionário desatento",
    difficulty: "Médio"
},
{
    question: "O que significa o princípio da confidencialidade?",
    options: [
        "Garantir que os dados estejam disponíveis quando necessários",
        "Garantir que apenas pessoas autorizadas acessem a informação",
        "Manter os dados atualizados",
        "Permitir acesso irrestrito à informação"
    ],
    answer: "Garantir que apenas pessoas autorizadas acessem a informação",
    difficulty: "Fácil"
},
{
    question: "O que é uma política de backup eficaz?",
    options: [
        "Guardar todos os dados em um HD externo",
        "Fazer backup somente quando houver falha",
        "Ter cópias regulares, em locais distintos e testadas",
        "Criar senhas fortes para todos os arquivos"
    ],
    answer: "Ter cópias regulares, em locais distintos e testadas",
    difficulty: "Difícil"
},
{
    question: "Por que atualizações de software são importantes para a segurança?",
    options: [
        "Para melhorar a velocidade do computador",
        "Para instalar novos programas",
        "Para corrigir vulnerabilidades conhecidas",
        "Para aumentar o armazenamento disponível"
    ],
    answer: "Para corrigir vulnerabilidades conhecidas",
    difficulty: "Fácil"
},
{
    question: "O que é autenticação multifator (MFA)?",
    options: [
        "Usar várias senhas diferentes",
        "Autenticar-se em vários sistemas ao mesmo tempo",
        "Combinar dois ou mais métodos de verificação",
        "Permitir acesso a múltiplos usuários"
    ],
    answer: "Combinar dois ou mais métodos de verificação",
    difficulty: "Fácil"
},
{
    question: "O que um ataque de força bruta tenta fazer?",
    options: [
        "Bloquear serviços com tráfego excessivo",
        "Enviar e-mails falsos com vírus",
        "Tentar todas as combinações de senha possíveis",
        "Enganar o usuário para instalar malware"
    ],
    answer: "Tentar todas as combinações de senha possíveis",
    difficulty: "Médio"
},
{
    question: "O que é o princípio da integridade da informação?",
    options: [
        "A informação está sempre acessível",
        "A informação é verdadeira e completa",
        "A informação é protegida contra leitura",
        "A informação pode ser modificada por qualquer um"
    ],
    answer: "A informação é verdadeira e completa",
    difficulty: "Fácil"
},
{
    question: "Qual destas práticas ajuda a garantir a integridade dos dados?",
    options: [
        "Criptografia",
        "Antivírus",
        "Assinatura digital",
        "Firewall"
    ],
    answer: "Assinatura digital",
    difficulty: "Médio"
},
{
    question: "Qual dos itens a seguir é uma ameaça à disponibilidade da informação?",
    options: [
        "Backup criptografado",
        "Queda de energia",
        "Firewall mal configurado",
        "Usuário com acesso não autorizado"
    ],
    answer: "Queda de energia",
    difficulty: "Médio"
},
{
    question: "Qual é o papel de um antivírus?",
    options: [
        "Reduzir o consumo de energia do computador",
        "Melhorar a performance de jogos",
        "Detectar e remover softwares maliciosos",
        "Evitar atualizações automáticas"
    ],
    answer: "Detectar e remover softwares maliciosos",
    difficulty: "Fácil"
},
{
    question: "Por que senhas devem ser trocadas periodicamente?",
    options: [
        "Para evitar o uso repetido da mesma senha",
        "Para reduzir a velocidade de acesso",
        "Para aumentar o consumo de memória",
        "Para gerar alertas automáticos"
    ],
    answer: "Para evitar o uso repetido da mesma senha",
    difficulty: "Fácil"
},
{
    question: "O que é um ataque man-in-the-middle?",
    options: [
        "Interceptação de comunicação entre duas partes",
        "Invasão de rede sem fio",
        "Engenharia social por e-mail",
        "Ataque a banco de dados com injeção de SQL"
    ],
    answer: "Interceptação de comunicação entre duas partes",
    difficulty: "Difícil"
},
{
    question: "Quais cuidados tomar ao utilizar redes Wi-Fi públicas?",
    options: [
        "Evitar transações bancárias",
        "Utilizar VPNs",
        "Desconfiar de redes sem senha",
        "Todas as alternativas estão corretas"
    ],
    answer: "Todas as alternativas estão corretas",
    difficulty: "Médio"
},
{
    question: "O que caracteriza um ransomware?",
    options: [
        "É um vírus que coleta dados bancários",
        "É um programa que impede o acesso aos dados até que um resgate seja pago",
        "É um software que rouba senhas",
        "É uma técnica de engenharia social"
    ],
    answer: "É um programa que impede o acesso aos dados até que um resgate seja pago",
    difficulty: "Médio"
},
{
    question: "Qual dos seguintes é um exemplo de autenticação de dois fatores?",
    options: ["Senha e nome de usuário", "Cartão de acesso e PIN", "Senha e pista de senha", "Nome de usuário e endereço de e-mail"],
    answer: "Cartão de acesso e PIN",
    difficulty: "Fácil"
},
{
    question: "O que define um ransomware?",
    options: ["Programa que registra as teclas pressionadas", "Software que rouba senhas", "Malware que bloqueia acesso aos dados e exige resgate", "Ferramenta de varredura de redes"],
    answer: "Malware que bloqueia acesso aos dados e exige resgate",
    difficulty: "Médio"
},
{
    question: "Qual dessas práticas é mais segura ao criar senhas?",
    options: ["Usar nomes de familiares", "Reutilizar senhas", "Criar uma senha longa e única", "Adicionar datas de nascimento"],
    answer: "Criar uma senha longa e única",
    difficulty: "Fácil"
},
{
    question: "O que é um ataque DDoS?",
    options: ["Tentativa de acesso não autorizado", "Ataque de engenharia social", "Sobrecarga de tráfego para tornar um sistema indisponível", "Interceptação de dados criptografados"],
    answer: "Sobrecarga de tráfego para tornar um sistema indisponível",
    difficulty: "Médio"
},
{
    question: "Qual é o papel da criptografia na segurança da informação?",
    options: ["Criar backups", "Facilitar o acesso remoto", "Proteger a confidencialidade dos dados", "Bloquear sites maliciosos"],
    answer: "Proteger a confidencialidade dos dados",
    difficulty: "Fácil"
},
{
    question: "Por que o uso de software pirata representa um risco à segurança?",
    options: ["É mais barato", "É ilegal", "Pode conter malware e não recebe atualizações", "É difícil de usar"],
    answer: "Pode conter malware e não recebe atualizações",
    difficulty: "Médio"
},
{
    question: "Qual dos seguintes ataques visa capturar informações inseridas em formulários online?",
    options: ["SQL Injection", "Cross-site Scripting (XSS)", "Phishing", "DDoS"],
    answer: "Cross-site Scripting (XSS)",
    difficulty: "Difícil"
},
{
    question: "O que é um antivírus?",
    options: ["Um firewall", "Um protocolo de segurança", "Um software que detecta e remove malwares", "Um ataque cibernético"],
    answer: "Um software que detecta e remove malwares",
    difficulty: "Fácil"
},
{
    question: "Qual é a melhor definição de 'confidencialidade' em segurança da informação?",
    options: ["Acesso autorizado apenas por pessoas permitidas", "Disponibilidade de dados em qualquer momento", "Precisão das informações", "Facilidade de compartilhamento de dados"],
    answer: "Acesso autorizado apenas por pessoas permitidas",
    difficulty: "Fácil"
},
{
    question: "O que significa 'integridade' da informação?",
    options: ["Estar criptografada", "Poder ser acessada remotamente", "Estar completa e não ter sido alterada indevidamente", "Estar visível ao usuário final"],
    answer: "Estar completa e não ter sido alterada indevidamente",
    difficulty: "Fácil"
},
{
    question: "Qual é o principal objetivo de uma política de segurança da informação?",
    options: ["Restringir o uso de internet", "Definir regras para proteger os ativos de informação", "Reduzir o uso de energia", "Melhorar o design do site"],
    answer: "Definir regras para proteger os ativos de informação",
    difficulty: "Médio"
},
{
    question: "O que é um certificado digital?",
    options: ["Comprovante de backup", "Arquivo de segurança de redes Wi-Fi", "Documento eletrônico que autentica a identidade de um usuário", "Senha criptografada"],
    answer: "Documento eletrônico que autentica a identidade de um usuário",
    difficulty: "Médio"
},
{
    question: "Qual dessas ações ajuda a evitar ataques de força bruta?",
    options: ["Usar firewall", "Bloquear IPs suspeitos", "Implementar limites de tentativas de login", "Desativar logs de erro"],
    answer: "Implementar limites de tentativas de login",
    difficulty: "Difícil"
},
{
    question: "Como um keylogger compromete a segurança?",
    options: ["Interrompendo o sistema", "Registrando as teclas digitadas", "Desativando antivírus", "Instalando atualizações não autorizadas"],
    answer: "Registrando as teclas digitadas",
    difficulty: "Médio"
},
{
    question: "O que é spoofing?",
    options: ["Interceptação de pacotes", "Falsificação de identidade para enganar sistemas ou usuários", "Ataque de negação de serviço", "Destruição de dados locais"],
    answer: "Falsificação de identidade para enganar sistemas ou usuários",
    difficulty: "Difícil"
},
{
    question: "O que é o princípio do menor privilégio?",
    options: ["Permitir acesso a todos os usuários", "Dar acesso irrestrito ao administrador", "Conceder a cada usuário somente o necessário para seu trabalho", "Restringir todos os acessos"],
    answer: "Conceder a cada usuário somente o necessário para seu trabalho",
    difficulty: "Médio"
},

    {
        question: "Qual o objetivo principal de uma política de segurança da informação?",
        options: ["Proteger ativos digitais", "Aumentar a velocidade da rede", "Economizar energia", "Melhorar o marketing digital"],
        answer: "Proteger ativos digitais",
        difficulty: "Fácil"
    },
    {
        question: "O que é um ataque de phishing?",
        options: ["Uso de força bruta", "Engano para obter dados sensíveis", "Ataque a hardware", "Monitoramento de rede sem permissão"],
        answer: "Engano para obter dados sensíveis",
        difficulty: "Fácil"
    },
    {
        question: "O que caracteriza um malware do tipo ransomware?",
        options: ["Rouba senhas do navegador", "Destrói arquivos permanentemente", "Criptografa dados e exige resgate", "Espiona usuários remotamente"],
        answer: "Criptografa dados e exige resgate",
        difficulty: "Médio"
    },
    {
        question: "Qual dos seguintes é um exemplo de autenticação multifator (MFA)?",
        options: ["Senha e pergunta secreta", "Biometria e token", "PIN apenas", "Usuário e senha"],
        answer: "Biometria e token",
        difficulty: "Médio"
    },
    {
        question: "Qual é o papel de um firewall em uma rede de computadores?",
        options: ["Aumentar o alcance da rede", "Melhorar a velocidade de internet", "Bloquear acessos não autorizados", "Organizar arquivos"],
        answer: "Bloquear acessos não autorizados",
        difficulty: "Fácil"
    },
    {
        question: "O que significa o princípio do menor privilégio?",
        options: ["Todos têm acesso total", "Apenas administradores têm acesso", "Conceder o mínimo necessário para execução da tarefa", "Restringir todo e qualquer acesso"],
        answer: "Conceder o mínimo necessário para execução da tarefa",
        difficulty: "Médio"
    },
    {
        question: "O que caracteriza um ataque DDoS?",
        options: ["Envia e-mails maliciosos", "Acessa contas bancárias", "Sobrecarrega sistemas com múltiplas requisições", "Criptografa dados da vítima"],
        answer: "Sobrecarrega sistemas com múltiplas requisições",
        difficulty: "Médio"
    },
    {
        question: "Como um certificado digital ajuda na segurança da informação?",
        options: ["Facilita o login", "Autentica identidade e garante integridade", "Aumenta a velocidade da internet", "Apaga cookies automaticamente"],
        answer: "Autentica identidade e garante integridade",
        difficulty: "Médio"
    },
    {
        question: "O que é um exploit?",
        options: ["Backup de segurança", "Atualização de software", "Código que explora vulnerabilidades", "Firewall desatualizado"],
        answer: "Código que explora vulnerabilidades",
        difficulty: "Difícil"
    },
    {
        question: "Qual dessas ações reduz a superfície de ataque?",
        options: ["Remover serviços desnecessários", "Instalar mais programas", "Compartilhar senhas", "Desativar o firewall"],
        answer: "Remover serviços desnecessários",
        difficulty: "Médio"
    },
    {
        question: "Por que é importante atualizar softwares regularmente?",
        options: ["Evita travamentos", "Corrige vulnerabilidades conhecidas", "Melhora o design", "Reduz o uso da internet"],
        answer: "Corrige vulnerabilidades conhecidas",
        difficulty: "Fácil"
    },
    {
        question: "Qual dessas senhas é considerada mais segura?",
        options: ["123456", "senha123", "abcde", "G7!xZp2#vQ"],
        answer: "G7!xZp2#vQ",
        difficulty: "Fácil"
    },
    {
        question: "O que é um backdoor em sistemas de segurança?",
        options: ["Falha no firewall", "Caminho oculto para acesso não autorizado", "Interface gráfica insegura", "Porta física destravada"],
        answer: "Caminho oculto para acesso não autorizado",
        difficulty: "Difícil"
    },
    {
        question: "O que é criptografia?",
        options: ["Sistema de backup", "Método de compressão", "Transformação de dados para torná-los ilegíveis sem chave", "Processo de deletar arquivos"],
        answer: "Transformação de dados para torná-los ilegíveis sem chave",
        difficulty: "Fácil"
    },
    {
        question: "O que é um ataque de força bruta?",
        options: ["Ataque direto ao hardware", "Tentativa sistemática de todas as senhas possíveis", "Engenharia social avançada", "Interferência física em roteadores"],
        answer: "Tentativa sistemática de todas as senhas possíveis",
        difficulty: "Médio"
    },
    {
        question: "Qual é a principal vantagem do uso de VPN?",
        options: ["Melhorar sinal Wi-Fi", "Acelerar downloads", "Proteger dados transmitidos e ocultar IP", "Desinstalar vírus"],
        answer: "Proteger dados transmitidos e ocultar IP",
        difficulty: "Fácil"
    },
    {
        question: "Qual a finalidade de um IDS (Intrusion Detection System)?",
        options: ["Bloquear spam", "Monitorar e detectar acessos suspeitos", "Verificar temperatura de servidores", "Realizar backup automático"],
        answer: "Monitorar e detectar acessos suspeitos",
        difficulty: "Difícil"
    },
    {
        question: "O que é o hashing em segurança da informação?",
        options: ["Tipo de compressão de imagens", "Técnica para acelerar downloads", "Conversão de dados em valor fixo irreversível", "Processo de atualizar sistemas"],
        answer: "Conversão de dados em valor fixo irreversível",
        difficulty: "Difícil"
    
        ,question: "O que significa a sigla SOC em segurança da informação?",
        options: ["System Operation Control", "Security Operations Center", "Standard Organization Compliance", "Secure Online Communication"],
        answer: "Security Operations Center",
        difficulty: "Médio"
    },
    {
        question: "Qual é a finalidade de um honeypot em segurança da informação?",
        options: ["Aumentar a velocidade da rede", "Simular vulnerabilidades para atrair atacantes", "Proteger e-mails corporativos", "Garantir backups frequentes"],
        answer: "Simular vulnerabilidades para atrair atacantes",
        difficulty: "Difícil"
    },
    {
        question: "Qual destas práticas ajuda na proteção contra ransomware?",
        options: ["Deixar o antivírus desatualizado", "Executar qualquer anexo de e-mail", "Fazer backups regulares", "Desabilitar firewall"],
        answer: "Fazer backups regulares",
        difficulty: "Fácil"
    },
    {
        question: "O que caracteriza um ataque de negação de serviço (DoS)?",
        options: ["Roubo de identidade", "Interceptação de dados", "Tornar um sistema indisponível", "Envio de spam"],
        answer: "Tornar um sistema indisponível",
        difficulty: "Médio"
    },
    {
        question: "Qual das opções representa um tipo de autenticação forte?",
        options: ["Senha simples", "Senha + captcha", "Autenticação de dois fatores", "Somente biometria"],
        answer: "Autenticação de dois fatores",
        difficulty: "Médio"
    },
    {
        question: "Qual a função do protocolo HTTPS?",
        options: ["Enviar pacotes IP", "Aumentar a velocidade da conexão", "Proteger a comunicação na web", "Filtrar spam"],
        answer: "Proteger a comunicação na web",
        difficulty: "Fácil"
    },
    {
        question: "Um ataque do tipo 'man-in-the-middle' ocorre quando:",
        options: ["O atacante se passa por um roteador", "O usuário esquece sua senha", "A rede é invadida por força bruta", "O firewall é desativado manualmente"],
        answer: "O atacante se passa por um roteador",
        difficulty: "Difícil"
    },
    {
        question: "O que define a confidencialidade da informação?",
        options: ["A informação está acessível somente a quem tem permissão", "A informação é criptografada sempre", "Os backups são feitos corretamente", "A informação pode ser acessada por qualquer pessoa"],
        answer: "A informação está acessível somente a quem tem permissão",
        difficulty: "Fácil"
    },
    {
        question: "Um ataque de phishing geralmente envolve:",
        options: ["Quebra de senha por força bruta", "Captura de tráfego DNS", "Envio de e-mails fraudulentos", "Invasão física ao servidor"],
        answer: "Envio de e-mails fraudulentos",
        difficulty: "Fácil"
    },
    {
        question: "O que é autenticação multifator (MFA)?",
        options: ["Login com senha", "Login com e-mail e senha", "Login com múltiplas formas de verificação", "Autenticação por IP"],
        answer: "Login com múltiplas formas de verificação",
        difficulty: "Médio"
    },
    {
        question: "Qual destes **não** é um vetor comum de ataque cibernético?",
        options: ["E-mail malicioso", "Site infectado", "Firewall configurado corretamente", "Dispositivos USB comprometidos"],
        answer: "Firewall configurado corretamente",
        difficulty: "Fácil"
    },
    {
        question: "A integridade da informação está relacionada a:",
        options: ["Garantir que a informação permaneça inalterada", "Disponibilizar backups", "Proteger senhas de usuários", "Aumentar a performance do sistema"],
        answer: "Garantir que a informação permaneça inalterada",
        difficulty: "Médio"
    },
    {
        question: "Qual ferramenta é usada para identificar vulnerabilidades em sistemas?",
        options: ["PowerPoint", "Wireshark", "Nmap", "Outlook"],
        answer: "Nmap",
        difficulty: "Difícil"
    },
    {
        question: "O que é um certificado digital?",
        options: ["Uma senha criptografada", "Uma licença de software", "Uma forma de autenticação eletrônica", "Um antivírus específico"],
        answer: "Uma forma de autenticação eletrônica",
        difficulty: "Médio"
    },
    {
        question: "Qual é o objetivo de uma política de segurança da informação?",
        options: ["Evitar o uso da internet", "Definir regras para proteção da informação", "Permitir acesso livre aos dados", "Remover antivírus da empresa"],
        answer: "Definir regras para proteção da informação",
        difficulty: "Fácil"
    },
    {
        question: "Ataques de zero-day são perigosos porque:",
        options: ["São fáceis de detectar", "Não existem patches disponíveis", "São sempre físicos", "Utilizam senhas fracas"],
        answer: "Não existem patches disponíveis",
        difficulty: "Difícil"
    },
    {
        question: "O que define a disponibilidade da informação?",
        options: ["A informação pode ser acessada quando necessário", "A informação está criptografada", "A informação está restrita", "A informação foi apagada"],
        answer: "A informação pode ser acessada quando necessário",
        difficulty: "Fácil"
        
        },
        {
            question: "O que é criptografia assimétrica?",
            options: ["Usa a mesma chave para criptografar e descriptografar", "Requer hardware especial", "Utiliza duas chaves diferentes", "Só é usada em bancos"],
            answer: "Utiliza duas chaves diferentes",
            difficulty: "Médio"
        },
        {
            question: "Qual destas práticas ajuda a proteger a privacidade online?",
            options: ["Usar redes públicas sem VPN", "Compartilhar senhas com amigos", "Utilizar autenticação de dois fatores", "Postar localização em tempo real"],
            answer: "Utilizar autenticação de dois fatores",
            difficulty: "Fácil"
        },
        {
            question: "O que é um honeypot?",
            options: ["Um tipo de vírus", "Um servidor falso para atrair atacantes", "Software de backup", "Rede segura de computadores"],
            answer: "Um servidor falso para atrair atacantes",
            difficulty: "Difícil"
        },
        {
            question: "O que é necessário para configurar uma VPN?",
            options: ["Um roteador", "Uma conexão com a internet", "Um serviço VPN e credenciais de acesso", "Apenas um firewall"],
            answer: "Um serviço VPN e credenciais de acesso",
            difficulty: "Médio"
        },
        {
            question: "O que representa um certificado SSL em um site?",
            options: ["Que o site é lento", "Que o site é falso", "Que o site usa comunicação criptografada", "Que o site está em manutenção"],
            answer: "Que o site usa comunicação criptografada",
            difficulty: "Fácil"
        },
        {
            question: "O que é spoofing?",
            options: ["Interceptar dados criptografados", "Disfarçar identidade para enganar sistemas ou pessoas", "Rastreamento de IPs", "Análise de vulnerabilidades"],
            answer: "Disfarçar identidade para enganar sistemas ou pessoas",
            difficulty: "Médio"
        },
        {
            question: "Qual ferramenta é comumente usada para análise de pacotes de rede?",
            options: ["Wireshark", "Photoshop", "Firefox", "Excel"],
            answer: "Wireshark",
            difficulty: "Difícil"
        },
        {
            question: "Qual dessas é uma boa prática de segurança para e-mails?",
            options: ["Clicar em links desconhecidos", "Ignorar remetentes verificados", "Verificar o domínio do remetente", "Abrir anexos de qualquer origem"],
            answer: "Verificar o domínio do remetente",
            difficulty: "Fácil"
        },
        {
            question: "O que é um keylogger?",
            options: ["Software que protege o teclado", "Hardware de segurança", "Programa que registra tudo que é digitado", "Antivírus corporativo"],
            answer: "Programa que registra tudo que é digitado",
            difficulty: "Médio"
        },
        {
            question: "Qual a função de um IDS (Intrusion Detection System)?",
            options: ["Bloquear vírus", "Detectar atividades suspeitas na rede", "Criar backups", "Acelerar a internet"],
            answer: "Detectar atividades suspeitas na rede",
            difficulty: "Médio"
        },
        {
            question: "O que é uma ameaça interna?",
            options: ["Um malware externo", "Um ataque por e-mail", "Uma falha física no servidor", "Riscos vindos de usuários autorizados"],
            answer: "Riscos vindos de usuários autorizados",
            difficulty: "Difícil"
        },
        {
            question: "Quais são os três pilares da Segurança da Informação?",
            options: ["Antivírus, firewall e VPN", "Backup, atualização e senhas", "Confidencialidade, integridade e disponibilidade", "Hardware, software e pessoas"],
            answer: "Confidencialidade, integridade e disponibilidade",
            difficulty: "Fácil"
        },
        {
            question: "Qual desses métodos é mais seguro para armazenar senhas?",
            options: ["Em um caderno", "Em um arquivo .txt", "Em um gerenciador de senhas confiável", "Memorizar todas"],
            answer: "Em um gerenciador de senhas confiável",
            difficulty: "Fácil"
        },
        {
            question: "O que é um ataque zero-day?",
            options: ["Um ataque muito lento", "Exploração de falha ainda desconhecida pelos desenvolvedores", "Erro de digitação", "Problema de hardware"],
            answer: "Exploração de falha ainda desconhecida pelos desenvolvedores",
            difficulty: "Difícil"
        },
        {
            question: "Qual é a importância de aplicar patches de segurança?",
            options: ["Melhorar o design do sistema", "Evitar ataques que exploram falhas conhecidas", "Aumentar o desempenho gráfico", "Eliminar arquivos duplicados"],
            answer: "Evitar ataques que exploram falhas conhecidas",
            difficulty: "Médio"
        },
        {
            question: "O que é uma política de segurança da informação?",
            options: ["Um antivírus empresarial", "Conjunto de regras e diretrizes para proteger informações", "Um certificado digital", "Um software de firewall"],
            answer: "Conjunto de regras e diretrizes para proteger informações",
            difficulty: "Médio"
            
                ,question: "O que é a ISO/IEC 27001?",
                options: ["Um antivírus", "Um firewall", "Uma norma de segurança da informação", "Uma linguagem de programação"],
                answer: "Uma norma de segurança da informação",
                difficulty: "Médio"
            },
            {
                question: "Qual é o objetivo principal da criptografia?",
                options: ["Ocultar informações para dificultar o acesso", "Reduzir o tamanho do arquivo", "Corrigir erros em arquivos", "Melhorar o desempenho de redes"],
                answer: "Ocultar informações para dificultar o acesso",
                difficulty: "Fácil"
            },
            {
                question: "O que é considerado um ataque de phishing?",
                options: ["Um ataque físico a servidores", "Uma tentativa de enganar o usuário para obter informações sensíveis", "Um tipo de malware que destrói dados", "Uma falha de hardware"],
                answer: "Uma tentativa de enganar o usuário para obter informações sensíveis",
                difficulty: "Fácil"
            },
            {
                question: "O que é uma vulnerabilidade zero-day?",
                options: ["Uma falha já conhecida e corrigida", "Uma falha detectada antes de ser conhecida publicamente", "Um backup automático", "Uma senha fraca"],
                answer: "Uma falha detectada antes de ser conhecida publicamente",
                difficulty: "Difícil"
            },
            {
                question: "Qual é uma medida importante para garantir a disponibilidade da informação?",
                options: ["Backup regular", "Criptografia simétrica", "Uso de proxy", "Senhas complexas"],
                answer: "Backup regular",
                difficulty: "Médio"
            },
            {
                question: "Qual desses é um exemplo de autenticação multifator?",
                options: ["Senha e nome de usuário", "Senha e token de segurança", "Usuário e email", "Senha e IP"],
                answer: "Senha e token de segurança",
                difficulty: "Fácil"
            },
            {
                question: "O que é um certificado digital?",
                options: ["Uma prova de que o software está atualizado", "Uma tecnologia de backup", "Um meio de autenticar identidades em ambiente digital", "Um antivírus online"],
                answer: "Um meio de autenticar identidades em ambiente digital",
                difficulty: "Médio"
            },
            {
                question: "Qual das alternativas NÃO representa um tipo de malware?",
                options: ["Trojan", "Spyware", "Firewall", "Ransomware"],
                answer: "Firewall",
                difficulty: "Fácil"
            },
            {
                question: "Por que é importante manter o sistema operacional atualizado?",
                options: ["Para ter novos temas visuais", "Para melhorar a velocidade do mouse", "Para corrigir falhas de segurança", "Para reduzir o consumo de energia"],
                answer: "Para corrigir falhas de segurança",
                difficulty: "Fácil"
            },
            {
                question: "Qual o principal objetivo da segurança da informação?",
                options: ["Reduzir custos operacionais", "Evitar downloads de programas", "Garantir confidencialidade, integridade e disponibilidade", "Melhorar o desempenho de sistemas"],
                answer: "Garantir confidencialidade, integridade e disponibilidade",
                difficulty: "Fácil"
            },
            {
                question: "O que é autenticação biométrica?",
                options: ["Uso de múltiplas senhas", "Validação com base em características físicas", "Conexão via Bluetooth", "Acesso remoto"],
                answer: "Validação com base em características físicas",
                difficulty: "Fácil"
            },
            {
                question: "Qual é o risco de usar a mesma senha para múltiplas contas?",
                options: ["Diminuição da produtividade", "Risco de sincronização incorreta", "Maior vulnerabilidade em caso de vazamento", "Erro de digitação frequente"],
                answer: "Maior vulnerabilidade em caso de vazamento",
                difficulty: "Médio"
            },
            {
                question: "O que é a Política de Segurança da Informação (PSI)?",
                options: ["Um antivírus da empresa", "Um documento que estabelece diretrizes de segurança", "Software de controle de acesso", "Uma norma ISO específica"],
                answer: "Um documento que estabelece diretrizes de segurança",
                difficulty: "Médio"
            },
            {
                question: "Qual a melhor prática ao receber e-mails suspeitos com links?",
                options: ["Clicar para ver do que se trata", "Encaminhar para amigos", "Ignorar e excluir imediatamente", "Salvar o link em favoritos"],
                answer: "Ignorar e excluir imediatamente",
                difficulty: "Fácil"
            },
            {
                question: "O que é um exploit?",
                options: ["Um tipo de firewall", "Uma falha de hardware", "Um código que aproveita vulnerabilidades de software", "Um antivírus genérico"],
                answer: "Um código que aproveita vulnerabilidades de software",
                difficulty: "Difícil"
            },
            {
                question: "O que representa a 'integridade' na tríade da segurança da informação?",
                options: ["Garantia de que os dados são acessíveis quando necessário", "Proteção contra acesso não autorizado", "Garantia de que os dados não foram alterados ou corrompidos", "Capacidade de criptografar dados"],
                answer: "Garantia de que os dados não foram alterados ou corrompidos",
                difficulty: "Médio"
            }
        ];