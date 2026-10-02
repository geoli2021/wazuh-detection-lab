🎯 Detalhamento de Detecções
1. Kerberoasting (MITRE T1558.003)
Descrição: Requisições TGS com cifragem RC4 (0x17).

Telemetria: Event Log ID 4769.

Regra SIEM: 100010

2. Password Spraying (MITRE T1110.003)
Descrição: Múltiplas falhas de logon por IP.

Telemetria: Event Log ID 4625.

Regra SIEM: 100021

3. PowerShell Codificado (MITRE T1059.001)
Descrição: Uso de flags em Base64 (-e, -enc).

Telemetria: Sysmon Event ID 1.

Regra SIEM: 100030

Simulação:
impacket-atexec 'lab.local/admin:Senha@10.0.2.15'
'powershell.exe -e Q2xlYXItSG9zdA=='

4. Reverse Shell & Outbound (MITRE T1071/T1059)
Descrição: Conexões TCP de saída via shells.

Telemetria: Sysmon Event ID 3 e Event ID 1.

Regras SIEM: 91007 (Nível 12) / 100031 (Nível 11).

Simulação Listener:
nc -lvnp 4444

Simulação Execution:
impacket-atexec 'lab.local/admin:Senha@10.0.2.15'
'powershell.exe -Command "$c = New-Object'
'System.Net.Sockets.TCPClient("10.0.2.3",4444);'
'$c.Close()"'
