#!/bin/bash
# Nuclei 安装脚本

set -e

echo "[*] 安装 Nuclei Scanner..."

# 下载最新版本
NUCLEI_VERSION="v3.2.5"
NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"

# 检查系统架构
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
elif [ "$ARCH" = "aarch64" ]; then
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_arm64.zip"
fi

# 下载
echo "[*] 下载 Nuclei from $NUCLEI_URL"
cd /tmp
wget -q "$NUCLEI_URL" -O nuclei.zip

# 解压
unzip -q nuclei.zip
chmod +x nuclei

# 安装到系统路径
if [ -w "/usr/local/bin" ]; then
    mv nuclei /usr/local/bin/
    echo "[+] Nuclei 已安装到 /usr/local/bin/nuclei"
else
    mkdir -p ~/.local/bin
    mv nuclei ~/.local/bin/
    echo "[+] Nuclei 已安装到 ~/.local/bin/nuclei"
    echo "[*] 请确保 ~/.local/bin 在 PATH 中"
fi

# 验证安装
nuclei -version

# 下载模板库
echo "[*] 下载 Nuclei Templates..."
cd /root/.openclaw/workspace/projects/secscan-ai/backend/data
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git

echo "[+] Nuclei 安装完成！"
echo "[*] 模板库位置: /root/.openclaw/workspace/projects/secscan-ai/backend/data/nuclei-templates"
