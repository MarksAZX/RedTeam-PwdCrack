# RedTeam PwdCrack

Uma ferramenta de quebra de senhas e hashes com uma interface TUI (Text User Interface) visualmente impressionante, semelhante ao `btop`, projetada especificamente para operações de Red Team.

## Funcionalidades

- Interface TUI elegante e responsiva, inspirada no `btop`.
- Quebra de senhas de arquivos ZIP (incluindo protegidos com AES).
- Quebra de hashes (MD5, SHA1, SHA256) com wordlists.
- Monitoramento em tempo real de uso de CPU e RAM.
- Modo de força bruta e wordlist com suporte a arquivos grandes via streaming.
- Interface tabulada para alternar entre quebra de ZIP e Hash.
- Tabela de resultados para rastrear tentativas bem-sucedidas.
- Controles de início e parada para cada tarefa.

## Instalação

1. Clone este repositório.
2. Navegue até o diretório do projeto.
3. Instale as dependências: `pip install -r requirements.txt`
4. Execute a aplicação: `python main.py`

## Uso

1. Selecione a aba desejada (ZIP ou Hash).
2. Insira o caminho do arquivo ZIP ou o valor do hash.
3. Insira o caminho da wordlist.
4. Clique no botão "Start Cracking" para iniciar.
5. Monitore o progresso e os resultados na interface.

## Requisitos

- Python 3.8+
- Bibliotecas listadas em `requirements.txt`

## Licença

Esta ferramenta é destinada exclusivamente para fins legítimos de segurança cibernética, como testes de penetração autorizados e operações de Red Team. O uso indevido é responsabilidade do usuário.
