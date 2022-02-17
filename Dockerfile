# Builder stage for getting amanzon-neptune-tools.
FROM python:3.9.6-alpine as builder

RUN apk add git

RUN git clone --depth 1 --branch amazon-neptune-tools-1.4 \
    https://github.com/awslabs/amazon-neptune-tools /amazon-neptune-tools


# Stage for the graph-altimeter dev image.
FROM python:3.9.6-alpine

RUN apk add gcc musl-dev libffi-dev

COPY requirements/requirements.txt /tmp/
RUN pip install -r /tmp/requirements.txt  && rm -f /tmp/requirements.txt

RUN mkdir -p /app
WORKDIR /app

COPY bin /app/bin
COPY graph_altimeter /app/graph_altimeter

RUN mkdir -p /deps
COPY --from=builder \
    /amazon-neptune-tools/neptune-python-utils/neptune_python_utils \
    /deps/neptune_python_utils

ENV PYTHONPATH="/app:/deps"

ENTRYPOINT ["python", "bin/graph_altimeter_batch.py"]
