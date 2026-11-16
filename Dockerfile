# One image for every job (and later the API): `cirrus-ipinfo <command>`.
FROM docker.io/library/python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM docker.io/library/python:3.13-slim
COPY --from=build /install /usr/local
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin ipinfo
USER 10001
ENV PYTHONUNBUFFERED=1 IPINFO_WORK_DIR=/work
ENTRYPOINT ["cirrus-ipinfo"]
CMD ["--help"]
