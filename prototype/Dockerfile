# Builds either service: --build-arg PROJECT=Mif.Node or PROJECT=Mif.DemoApp
# Override SDK_IMAGE / RUNTIME_IMAGE if you build behind a proxy that needs its own CA baked in.
ARG SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0
ARG RUNTIME_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0

FROM ${SDK_IMAGE} AS build
ARG PROJECT
WORKDIR /build
COPY src/ src/
RUN dotnet publish src/${PROJECT}/${PROJECT}.csproj -c Release -o /app

FROM ${RUNTIME_IMAGE}
ARG PROJECT
WORKDIR /app
COPY --from=build /app .
# The node keeps its snapshot signing key here; mount a volume so it survives the container.
RUN mkdir -p /data/keys && chown -R $APP_UID /data
USER $APP_UID
ENV APP_DLL=${PROJECT}.dll
ENTRYPOINT ["sh", "-c", "exec dotnet $APP_DLL"]
