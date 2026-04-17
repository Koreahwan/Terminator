FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" websockets psycopg2-binary neo4j requests
COPY web/ ./web/
EXPOSE 3000
CMD ["uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "3000"]
