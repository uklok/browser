FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        fonts-liberation \
        fonts-noto-color-emoji \
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
        xvfb \
    && install -d -m 0755 /usr/share/keyrings \
    && curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
        | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
        > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 --shell /bin/bash browser \
    && install -d -o browser -g browser -m 0700 /data/chrome /run/browser

COPY --chmod=0755 scripts/entrypoint.sh /usr/local/bin/browser-entrypoint
COPY --chmod=0755 scripts/start-xvfb.sh /usr/local/bin/start-xvfb
COPY --chmod=0755 scripts/start-chrome.sh /usr/local/bin/start-chrome
COPY --chmod=0755 scripts/start-vnc.sh /usr/local/bin/start-vnc
COPY --chmod=0755 scripts/start-novnc.sh /usr/local/bin/start-novnc
COPY --chmod=0755 scripts/start-cdp-relay.sh /usr/local/bin/start-cdp-relay
COPY --chmod=0755 scripts/healthcheck.sh /usr/local/bin/browser-healthcheck
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
