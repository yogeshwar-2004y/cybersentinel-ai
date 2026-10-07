FROM python:3.12-slim
ARG INSTALL_SEMANTIC=false
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 STATE_DIR=/app/state
WORKDIR /app
COPY requirements*.txt ./
RUN python -m pip install --no-cache-dir -r requirements-core.txt && \
    if [ "$INSTALL_SEMANTIC" = "true" ]; then \
      python -m pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
      python -m pip install --no-cache-dir -r requirements.txt; \
    fi
RUN useradd --create-home --uid 10001 appuser
COPY --chown=appuser:appuser . /app
RUN mkdir -p /app/state && chown appuser:appuser /app/state
USER appuser
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health')"
CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "8501"]
