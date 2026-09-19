FROM python:3.10-slim
WORKDIR /app
COPY . /app
EXPOSE 22 23 80 2222
CMD ["python", "main.py"]