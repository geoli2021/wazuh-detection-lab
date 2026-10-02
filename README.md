# 🛡️ Active Directory & Wazuh SIEM Detection Engineering Lab

## 📌 Visão Geral do Projeto
Este repositório documenta um ambiente de **Engenharia de Detecção** focado na segurança de infraestruturas Active Directory. 

O objetivo do laboratório é simular vetores de ataque reais mapeados no framework **MITRE ATT&CK** (Red Team) e correlacionar a telemetria gerada no **Wazuh SIEM** com auxílio do **Sysmon** (Blue Team), desenvolvendo e validando regras de detecção customizadas em tempo real.

---

## 📐 Arquitetura do Laboratório

A infraestrutura foi dividida em sub-redes virtuais integradas por um firewall central:

* **Attacker (Kali Linux)** | IP: `10.0.2.3`
  * Origem dos disparos de teste (Impacket, NetExec, Netcat).
* **Domain Controller (DC01 - Windows Server 2022)** | IP: `192.168.1.10`
  * Controlador do domínio `lab.local` monitorado por Agent Wazuh, Sysmon v15.x e Security Event Log.
* **Workstation (WK01 - Windows 10/11)** | IP: `192.168.1.101`
  * Estação de trabalho do domínio monitorada por Agent Wazuh e Sysmon v15.x.
* **Firewall (pfSense)** | IP: `10.0.2.15` (WAN) / `192.168.1.1` (LAN)
  * Roteamento de rede, controle de banda e regras de encaminhamento.
* **SIEM (Wazuh Server)** | IP: `172.16.10.101`
  * Servidor central de análise de logs, aplicação de regras customizadas e visualização no Dashboard.

---

## 🎯 Táticas e Regras de Detecção Validadas

### 1. Kerberoasting (MITRE T1558.003)
* **Descrição:** Requisições TGS com cifragem RC4 (`0x17`) direcionadas a contas de serviço para extração offline de hashes.
* **Telemetria:** Windows Security Event Log (Event ID `4769`).
* **Regra Customizada:** `100010`

### 2. Password Spraying (MITRE T1110.003)
* **Descrição:** Tentativas de autenticação com senhas comuns contra múltiplas contas para evitar bloqueio por conta.
* **Telemetria:** Windows Security Event Log (Event ID `4625`).
* **Regra Customizada:** `100021` (Correlação temporal por IP de origem).

### 3. Execution of Encoded PowerShell (MITRE T1059.001)
* **Descrição:** Uso do interpretador PowerShell com parâmetros de codificação em Base64 (`-e`, `-enc`) para ofuscação de comandos.
* **Telemetria:** Sysmon Operational Log (Event ID `1` - Process Creation).
* **Regra Customizada:** `100030` (Alerta de Nível 10).

### 4. Reverse Shell & Network Outbound (MITRE T1071 / T1059)
* **Descrição:** Conexões TCP de saída ativas iniciadas por interpretadores de comando (`cmd.exe`, `powershell.exe`).
* **Telemetria:** Sysmon Operational Log (Event ID `3` - Network Connection e Event ID `1`).
* **Regras Disparadas:** `91007` (Nativa - Nível 12) e `100031` (Customizada - Nível 11).

---

## 📜 Regras Customizadas no Wazuh (`local_rules.xml`)

```xml
<group name="sysmon, redteam_detection,">

  <!-- Regra 100030: PowerShell Codificado -->
  <rule id="100030" level="10">
    <if_group>windows</if_group>
    <field name="win.system.providerName">^Microsoft-Windows-Sysmon$</field>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-e(nc(odedcommand)?)?</field>
    <description>Execução de PowerShell com argumento codificado detectada em $(win.system.computer)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <!-- Regra 100031: Conexão de Saída por Processo Shell -->
  <rule id="100031" level="11">
    <if_group>windows</if_group>
    <field name="win.system.providerName">^Microsoft-Windows-Sysmon$</field>
    <field name="win.system.eventID">^3$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)(cmd|powershell)\.exe</field>
    <description>Processo de Shell ($(win.eventdata.image)) estabeleceu conexão de rede de saída</description>
    <mitre>
      <id>T1071</id>
    </mitre>
  </rule>

</group>
