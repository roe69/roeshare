# RoeShare - a single Bun process. No build step and zero runtime dependencies,
# so the image is just the Bun runtime plus the source. Data lives on a volume.
FROM oven/bun:1-alpine

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
