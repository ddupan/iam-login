# Packages a native binary built beforehand; the build itself stays in scripts/gradle-in-docker so CI,
# local builds and this image use one toolchain. AOT fixes the enabled features, so build with:
#   scripts/gradle-in-docker nativeCompile \
#     "-PaotArgs=--iam.ad.enabled=true --iam.webauthn.enabled=true --iam.authorization-server.enabled=true"
#   docker build -t iam-login:VERSION .
# distroless java-base (no JRE): glibc plus the zlib the binary links (built on Oracle Linux 9, glibc 2.34; Debian 12 has 2.36).
FROM gcr.io/distroless/java-base-debian12:nonroot@sha256:a9930cad62d02853d7f3dede7281c4b916cbf74493c2d8d38564121aad92bf6c
COPY build/native/nativeCompile/iam-login /iam-login
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/iam-login"]
