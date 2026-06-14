# 🔒 API de Autenticação Segura (Node.js + MySQL)

Projeto prático desenvolvido para aplicar conceitos essenciais de **Desenvolvimento Seguro (DevSecOps)** e mitigar falhas comuns de cibersegurança (OWASP Top 10).

---

## 🛡️ Implementações de Segurança

* **Criptografia de Senhas (Bcrypt):** As senhas passam por hashing criptográfico com *Salt* (fator de custo 10) antes de irem para o banco. Nunca são salvas em texto limpo.
* **Proteção contra SQL Injection:** Uso de consultas preparadas (*Prepared Statements* com `?`) no driver `mysql2`, separando a estrutura da query dos dados do usuário.
* **Gestão de Credenciais (`.env`):** Dados sensíveis do banco isolados em variáveis de ambiente e protegidos via `.gitignore` para evitar vazamento no GitHub.
* **Defesa de Enumeração:** Mensagens de erro genéricas (`"E-mail ou senha incorretos!"`) para impedir que atacantes adivinhem quais e-mails estão cadastrados.
* **Controle de Tráfego (Rate Limiting):** Proteção ativa contra ataques de força bruta, limitando a 5 requisições por IP a cada 15 minutos nas rotas sensíveis.
* **Emissão de Tokens Seguros (JWT):** Geração de JSON Web Tokens no login para gerenciar a sessão do usuário de forma stateless e segura.
* **Rotas Protegidas (Middleware):** Validação de acesso a recursos restritos baseada na verificação da assinatura do JWT enviado nas requisições.

---

## 📦 Como Executar

1. **Instale as dependências:**
   ```bash
   npm install
--- 

# Crie a tabela no MySQL:
```SQL
CREATE DATABASE sistema_seguro;
USE sistema_seguro;
CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    senha VARCHAR(255) NOT NULL
);
```
---

## Configure o arquivo .env na raiz:
```Snippet de código
PORT=3000
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=SUA_SENHA_DO_MYSQL
DB_NAME=sistema_seguro
JWT_SECRET=UMA_CHAVE_SECRETA_E_SEGURA_AQUI
```
---

## Inicie o servidor:
```bash
node index.js
```
---