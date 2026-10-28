# syntax=docker/dockerfile:1
FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.source="https://github.com/uklok/browser" \
      org.opencontainers.image.description="Shared headful Chrome session with noVNC and CDP access"

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    set -eux; \
    test "$(dpkg --print-architecture)" = "amd64"; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        fonts-liberation \
        fonts-noto-color-emoji \
        gnupg \
        jq \
        novnc \
        openbox \
        procps \
        socat \
        supervisor \
        tini \
        websockify \
        x11-utils \
        x11vnc \
        xvfb; \
    install -d -m 0755 /usr/share/keyrings; \
    curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
        | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg; \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
        > /etc/apt/sources.list.d/google-chrome.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends google-chrome-stable; \
    rm -f /etc/apt/sources.list.d/google-chrome.list /usr/share/keyrings/google-chrome.gpg; \
    apt-get purge -y --auto-remove gnupg

RUN useradd --create-home --uid 1000 --shell /bin/bash browser \
    && install -d -o browser -g browser -m 0700 /data/chrome /run/browser

COPY --chmod=0755 scripts/ /usr/local/lib/browser/
RUN ln -s /usr/local/lib/browser/entrypoint.sh /usr/local/bin/browser-entrypoint \
    && ln -s /usr/local/lib/browser/start-xvfb.sh /usr/local/bin/start-xvfb \
    && ln -s /usr/local/lib/browser/start-chrome.sh /usr/local/bin/start-chrome \
    && ln -s /usr/local/lib/browser/start-vnc.sh /usr/local/bin/start-vnc \
    && ln -s /usr/local/lib/browser/start-novnc.sh /usr/local/bin/start-novnc \
    && ln -s /usr/local/lib/browser/start-cdp-relay.sh /usr/local/bin/start-cdp-relay \
    && ln -s /usr/local/lib/browser/healthcheck.sh /usr/local/bin/browser-healthcheck
COPY supervisord.conf /etc/supervisor/conf.d/browser.conf

ENV HOME=/home/browser \
    XDG_RUNTIME_DIR=/run/browser \
    DISPLAY=:99 \
    SCREEN_WIDTH=1440 \
    SCREEN_HEIGHT=900 \
    SCREEN_DEPTH=24 \
    CHROME_USER_DATA_DIR=/data/chrome \
    CHROME_INTERNAL_CDP_PORT=9223 \
    CDP_PORT=9222 \
    VNC_PORT=5900 \
    NOVNC_PORT=6080 \
    CHROME_START_URL=about:blank

VOLUME ["/data/chrome"]
EXPOSE 6080 9222

USER browser

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=6 \
    CMD ["/usr/local/bin/browser-healthcheck"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/browser-entrypoint"]
