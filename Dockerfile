FROM python:3.11-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# 复制后端代码
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# 创建数据目录
RUN mkdir -p /app/data

# 预下载Nuclei引擎
ENV NUCLEI_VERSION=3.2.5
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /tmp && \
    chmod +x /tmp/nuclei && \
    mv /tmp/nuclei /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    nuclei -version

# 预下载Nuclei模板
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /app/data/nuclei-templates || true

# 预下载Xray POC模板
RUN mkdir -p /app/xray-pocs && \
    git clone --depth 1 https://github.com/chaitin/xray.git /tmp/xray-src || true && \
    if [ -d /tmp/xray-src/pocs ]; then \
        cp /tmp/xray-src/pocs/*.yml /app/xray-pocs/ 2>/dev/null || true; \
    fi && \
    rm -rf /tmp/xray-src && \
    echo "Xray POC downloaded: $(ls /app/xray-pocs/*.yml 2>/dev/null | wc -l) files"

# 暴露端口
EXPOSE 8000

# 启动命令
CMD ["uvicorn", "secscan.main:app", "--host", "0.0.0.0", "--port", "8000"]
