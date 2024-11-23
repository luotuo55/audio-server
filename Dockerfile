# 使用Python官方镜像作为基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# 复制项目文件
COPY . /app/

# 创建必要的目录
RUN mkdir -p /app/voice /app/logs

# 设置权限
RUN chmod -R 755 /app

# 暴露端口
EXPOSE 8000

# 启动命令
CMD ["python", "static_server.py"]
