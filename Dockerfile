FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
COPY --chown=10001:10001 frp_ip_auth/ ./frp_ip_auth/
COPY --chown=10001:10001 gunicorn.conf.py ./
USER 10001:10001
EXPOSE 9000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:9000/health', timeout=2).close()"
CMD ["gunicorn", "--config", "gunicorn.conf.py", "frp_ip_auth.wsgi:application"]
