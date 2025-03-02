ARG DJANGO_CA_VERSION=2.2.1
FROM mathiasertl/django-ca:${DJANGO_CA_VERSION} AS build

# Install required dependencies
USER root
RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean &&  \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y git

# Install uv: https://docs.astral.sh/uv/guides/integration/docker/
COPY --from=ghcr.io/astral-sh/uv:0.6.3 /uv /uvx /bin/

# Activate virtual environment
ENV PATH="/usr/src/django-ca/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/usr/src/django-ca/.venv"

# Configure uv
ENV UV_PYTHON_PREFERENCE=only-system
ENV UV_LINK_MODE=copy

WORKDIR /install
ADD pyproject.toml ./
ADD django_ca_cmc/ ./django_ca_cmc/
ADD .git/ .git/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install .

FROM mathiasertl/django-ca:${DJANGO_CA_VERSION}
COPY conf/* /usr/src/django-ca/ca/conf/compose/
COPY nginx/cmc.conf /usr/src/django-ca/nginx/include.d/http/
COPY nginx/cmc.conf /usr/src/django-ca/nginx/include.d/https/
COPY --from=build /usr/src/django-ca/.venv/ /usr/src/django-ca/.venv/