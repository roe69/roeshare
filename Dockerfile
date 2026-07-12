# RoeShare - a single Bun process. No build step and zero runtime dependencies,
# so the image is just the Bun runtime plus the source. Data lives on a volume.
#
# Pinned to an exact version (not the floating "1-alpine" tag) plus its digest,
# resolved via `docker buildx imagetools inspect oven/bun:1-alpine` on
# 2026-07-12 (bun 1.3.14). Bump both together when intentionally upgrading.
FROM oven/bun:1.3.14-alpine@sha256:5acc90a93e91ff07bf72aa90a7c9f0fa189765aec90b47bdbf2152d2196383c0

WORKDIR /app
ENV NODE_ENV=production \
	HOST=0.0.0.0 \
	PORT=3300 \
	DATA_DIR=/data

# App source only - there are no node_modules to install.
COPY package.json ./
COPY src ./src
COPY public ./public

RUN mkdir -p /data && chown -R bun:bun /data /app
VOLUME ["/data"]
EXPOSE 3300

# Drop root: run as the non-root bun user (uid 1000) shipped by the base image.
USER bun

# Uses the unauthenticated /health endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
	CMD wget -q -O /dev/null http://127.0.0.1:3300/health || exit 1

CMD ["bun", "run", "src/server.js"]
