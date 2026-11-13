# ARM64 Python 3.12 Lambda image, aligned with the verified EPSS runtime.
FROM public.ecr.aws/lambda/python:3.12@sha256:23b45326890ac4b051c86e0938e6b86cbbe1d7f293dd32115908831b602bbd36

COPY lambda/cisa_silver/requirements.txt ${LAMBDA_TASK_ROOT}/requirements.txt
RUN pip install \
    --disable-pip-version-check \
    --no-cache-dir \
    --only-binary=:all: \
    --require-hashes \
    --requirement ${LAMBDA_TASK_ROOT}/requirements.txt \
    --target ${LAMBDA_TASK_ROOT} \
    && python -m pip check \
    && rm ${LAMBDA_TASK_ROOT}/requirements.txt

COPY src/threatflow ${LAMBDA_TASK_ROOT}/threatflow

CMD ["threatflow.transformation.cisa_silver_lambda.lambda_handler"]
