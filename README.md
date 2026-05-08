# APATE — SSH Deception Honeypot



<p align="center">
  <img src="demo.gif" alt="APATE" width="500"/>
</p>

APATE é um honeypot SSH profissional desenvolvido em Python que simula um servidor Linux real para atrair, enganar e analisar atacantes em tempo real.

---

## Como Funciona

O atacante conecta na porta 2222 via SSH, vê um banner legítimo do OpenSSH, autentica com credenciais reais, navega por um filesystem Linux falso e executa comandos — enquanto cada ação é silenciosamente registrada e analisada.

---

## Principais Recursos

### Shell Interativo com 20+ Comandos
```
ls / ls -la    ps aux         ip addr
cd             ifconfig       netstat -tulpn
cat            find           wget / curl
whoami         sudo           ssh
uname          hostname       python3
```

### Filesystem Virtual Realista
Árvore completa de diretórios Linux com conteúdo convincente:
- `/etc/passwd` com usuários fake
- `/etc/hosts` com IPs de servidores internos
- `/home/PC/.env` com credenciais de banco de dados
- `/var/log/auth.log` com histórico de acessos
- `/opt/app/config.yaml` com chaves de API

### Honeytoken — `secret_vault`
Diretório bloqueado que apresenta um hash bcrypt falso para fazer o atacante perder tempo tentando descriptografar:
```
Permission denied: secret_vault is encrypted.
Access requires decryption key.
Hash: $2b$14$XkJ9mNpQvRsWtYuZaAbBcDeFgHiJkLmNoPqRsTuVwXyZaAbBcDeFgH

```

### 6 Regras de Detecção
| Regra | Gatilho |
|-------|---------|
| `BRUTE_FORCE` | ≥ 5 tentativas de login falhas |
| `PRIVILEGE_ESCALATION` | Uso do comando `sudo` |
| `RECONNAISSANCE` | ≥ 3 comandos de reconhecimento |
| `LATERAL_MOVEMENT` | Tentativa de `ssh` para outro host |
| `DATA_EXFILTRATION` | Acesso a `.env`, `passwd`, `config.yaml` |
| `HONEYTOKEN_TRIGGERED` | Qualquer interação com `secret_vault` |

### Relatório de Ataque
Gerado automaticamente ao encerrar o servidor:
```
============================================================
HONEYPOT ATTACK ANALYSIS REPORT
============================================================

Total de IPs: 1
Alertas detectados: 10

[PRIVILEGE_ESCALATION] user: admin, severity: high
[RECONNAISSANCE] ip: x.x.x.x, count: 13, severity: medium
[LATERAL_MOVEMENT] command: ssh admin@192.168.1.10
[DATA_EXFILTRATION] filepath: /home/PC/.env, severity: Critical
[HONEYTOKEN_TRIGGERED] command: cd secret_vault, severity: critical
```

---

## Stack

- **Python 3.10+**
- **Paramiko** — protocolo SSH completo
- **bcrypt** — hash de senhas com migração automática de plaintext
- **Rate Limiter** — bloqueio por IP
- **Threat Intelligence** — base local de IPs maliciosos

---

## Instalação

```bash
git clone https://github.com/mateusdias96cs/honeypot-ssh.git
cd honeypot-ssh
pip install -r requirements.txt
python3 main.py
```

---

## Teste

```bash
# Conectar como atacante
ssh -p 2222 admin@<ip-alvo>
# senha: admin123
```

---

## Aviso Legal

Esta ferramenta é destinada exclusivamente para fins educacionais, pesquisa de segurança autorizada e ambientes de laboratório controlados. Não utilize em redes públicas sem autorização prévia.

---

## Licença

MIT License — veja o arquivo [LICENSE](LICENSE) para detalhes.

## Autor

**Mateus Dias** — Estudante de Cibersegurança | Blue Team

## Atualização
Projeto revisado e validado em maio de 2025.

[![GitHub](https://img.shields.io/badge/GitHub-mateusdias96cs-black)](https://github.com/mateusdias96cs)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mateus_Dias-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/mateusdiascs/)
