FROM apache/airflow:3.1.0-python3.12
USER root
COPY pyproject.toml /opt/threatflow/pyproject.toml
COPY src /opt/threatflow/src
COPY migrations /opt/threatflow/migrations
COPY alembic.ini /opt/threatflow/alembic.ini
RUN python -m venv /opt/threatflow-venv \
    && /opt/threatflow-venv/bin/pip install --no-cache-dir \
        lazy-object-proxy==1.12.0 \
        pendulum==3.1.0 \
        /opt/threatflow \
    && chown -R airflow:0 /opt/threatflow /opt/threatflow-venv
USER airflow
RUN pip install --no-cache-dir --no-deps /opt/threatflow
