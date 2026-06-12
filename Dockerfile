# just-shield 컨테이너 이미지 (ADR-0005 단계 ③).
# musl 정적 바이너리라 베이스 이미지가 필요 없다 — FROM scratch + 바이너리 하나.
# 셸도 패키지 매니저도 없으므로 이미지 자체의 공격 표면이 0에 가깝다.
# 빌드 컨텍스트: 릴리스 워크플로가 아치별 바이너리를 <arch>/just-shield로 배치한다 (RUN이 없어
# 에뮬레이션 없이 멀티 아치 빌드 가능).
FROM scratch
ARG TARGETARCH
LABEL org.opencontainers.image.source="https://github.com/kihyun1998/just-shield" \
      org.opencontainers.image.description="GitHub Actions 워크플로 공급망을 실행 전에 검사하는 CLI"
COPY ${TARGETARCH}/just-shield /just-shield
ENTRYPOINT ["/just-shield"]
