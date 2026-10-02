# 🛡️ Active Directory & Wazuh SIEM Detection Engineering Lab

Laboratório prático de **Engenharia de Detecção**, focado em simulação de ataques em ecossistema Active Directory (Red Team) e monitoramento defensivo com **Wazuh SIEM** e **Sysmon** (Blue Team).

---

## 📐 Topologia de Rede & Laboratório

* **Attacker (Kali Linux):** `10.0.2.3` — Ferramentas: Impacket, NetExec, Netcat.
* **Domain Controller (DC01):** `192.168.1.10` — Windows Server 2022 (`lab.local`).
* **Workstation (WK01):** `192.168.1.101` — Windows 10/11 Endpoint.
* **Firewall (pfSense):** `10.0.2.15` — Roteamento e regras de rede.
* **SIEM (Wazuh Server):** `172.16.10.101` — Manager, Decoders e Dashboard.

---

## 📁 Estrutura de Documentação do Repositório

* **[Documentação de Detecções & Testes](docs/detections.md):** Detalhamento das táticas MITRE ATT&CK testadas (Kerberoasting, Password Spraying, PowerShell Codificado e Reverse Shell) e comandos de simulação.
* **[Regras Customizadas do Wazuh](rules/local_rules.xml):** Ficheiro XML contendo todas as regras desenvolvidas e personalizadas no SIEM.

---

## 🛠️ Resumo das Tecnologias Utilizadas
- **SIEM & EDR:** Wazuh Manager v4.x + Sysmon v15.x
- **Rede & Serviços:** Active Directory, Kerberos, NTLM, pfSense
- **Simulação de Ataques:** Impacket (`atexec`, `psexec`), Netcat
