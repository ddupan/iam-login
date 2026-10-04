# Packages a native binary built beforehand; the build itself stays in scripts/gradle-in-docker so CI,
# local builds and this image use one toolchain. AOT fixes the enabled features, so build with:
#   scripts/gradle-in-docker nativeCompile \
#     "-PaotArgs=--iam.ad.enabled=true --iam.webauthn.enabled=true --iam.authorization-server.enabled=true"
#   docker build -t iam-login:VERSION .
# distroless base: the binary links glibc dynamically (built on Oracle Linux 9, glibc 2.34; Debian 12 has 2.36).
FROM gcr.io/distroless/base-debian12:nonroot@sha256:7f0c72cd138b442ae0deeb69c08b1acf5525439ba251a49ad93c320a061567e5
COPY --chmod=0555 build/native/nativeCompile/iam-login /iam-login
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/iam-login"]
