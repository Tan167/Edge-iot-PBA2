FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN useradd -r -u 10001 app && mkdir -p /data && chown app /data
USER app
CMD ["python", "app.py"]
