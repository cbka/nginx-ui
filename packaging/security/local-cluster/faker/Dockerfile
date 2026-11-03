FROM python:3.12-slim
WORKDIR /app
COPY server.py index.html app.js style.css ./
USER 65534:65534
EXPOSE 4184
CMD ["python", "-B", "server.py"]
