FROM python:3.9.6-alpine as python-base
RUN apk add gcc g++ musl-dev libffi-dev git


FROM python-base as pip-compile
ARG PIP_TOOLS_VERSION=6.5.1
RUN pip install "pip-tools==${PIP_TOOLS_VERSION}"
ENTRYPOINT ["pip-compile"]


FROM python-base as amazon-neptune-tools
ARG AMAZON_NEPTUNE_TOOLS_VERSION=1.12
RUN git clone --depth 1 --branch "amazon-neptune-tools-${AMAZON_NEPTUNE_TOOLS_VERSION}" https://github.com/awslabs/amazon-neptune-tools /amazon-neptune-tools


FROM python-base as service-base
RUN mkdir -p /app
WORKDIR /app
RUN mkdir -p /deps
COPY --from=amazon-neptune-tools \
	/amazon-neptune-tools/neptune-python-utils/neptune_python_utils \
	/deps/neptune_python_utils
ENV PYTHONPATH="/app:/deps"


FROM service-base as dev
COPY requirements/requirements-dev.txt /tmp/
RUN pip install -r /tmp/requirements-dev.txt && rm -f /tmp/requirements-dev.txt


FROM service-base as dev-altimeter
COPY requirements/requirements-dev-altimeter.txt /tmp/
RUN pip install -r /tmp/requirements-dev-altimeter.txt && rm -f /tmp/requirements-dev-altimeter.txt
COPY extern/altimeter/requirements.txt /tmp/
RUN pip install -r /tmp/requirements.txt && rm -f /tmp/requirements.txt
ENV PYTHONPATH="/app:/app/extern/altimeter:/deps"


FROM service-base
COPY requirements/requirements.txt /tmp/
RUN pip install -r /tmp/requirements.txt && rm -f /tmp/requirements.txt
COPY bin /app/bin
COPY graph_altimeter /app/graph_altimeter
ENTRYPOINT ["python", "bin/graph_altimeter_batch.py"]
