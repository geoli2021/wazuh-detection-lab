# 🎯 Detalhamento de Detecções e Simulação Prática

## 1. Kerberoasting (MITRE T1558.003)
* **Descrição:** Requisições TGS com encriptação RC4 (`0x17`) direcionadas a contas de serviço.
* **Telemetria:** Windows Security Event Log (`Event ID 4769`).
* **Regra SIEM:** `100010`

---

## 2. Password Spraying (MITRE T1110.003)
* **Descrição:** Múltiplas falhas de autenticação em sequência vindas do mesmo IP.
* **Telemetria:** Windows Security Event Log (`Event ID 4625`).
* **Regra SIEM:** `100021`

---

## 3. Execution of Encoded PowerShell (MITRE T1059.001)
* **Descrição:** Execução de comandos PowerShell ocultos com argumentos de codificação Base64 (`-e`, `-enc`).
* **Telemetria:** Sysmon Operational Log (`Event ID 1` - Process Creation).
* **Regra SIEM:** `100030`
* **Comando de Simulação (Kali Linux):**
  ```bash
  impacket-atexec 'lab.local/administrator:Lab@2026!Sec@10.0.2.15' 'powershell.exe -e Q2xlYXItSG9zdA=='
