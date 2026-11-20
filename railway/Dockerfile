FROM nikolaik/python-nodejs:python3.12-nodejs22-slim
WORKDIR /app
RUN pip install --no-cache-dir 'trackinizer[server]==0.1.14'
COPY railway/cloud_auth.py /app/cloud_auth.py
EXPOSE 8765
CMD ["python", "/app/cloud_auth.py"]
