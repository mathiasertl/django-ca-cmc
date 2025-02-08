ARG DJANGO_CA_VERSION=latest
FROM mathiasertl/django-ca:${DJANGO_CA_VERSION} AS build

# Install uv: https://docs.astral.sh/uv/guides/integration/docker/
COPY --from=ghcr.io/astral-sh/uv /uv /uvx /bin/

# Activate virtual environment
ENV PATH="/usr/src/django-ca/.venv/bin:$PATH"

# Configure uv
ENV UV_PYTHON_PREFERENCE=only-system
ENV UV_LINK_MODE=copy

WORKDIR /install
ADD pyproject.toml ./
ADD django_ca_cmc/ ./django_ca_cmc/

USER root
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install .

FROM mathiasertl/django-ca:${DJANGO_CA_VERSION}
COPY conf/* /usr/src/django-ca/ca/conf/compose/
COPY nginx/cmc.conf /usr/src/django-ca/nginx/include.d/http/
COPY nginx/cmc.conf /usr/src/django-ca/nginx/include.d/https/
COPY --from=build /usr/src/django-ca/.venv/ /usr/src/django-ca/.venv/