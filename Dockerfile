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

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 3300

# Uses the unauthenticated /healthz endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
	CMD wget -q -O /dev/null http://127.0.0.1:3300/healthz || exit 1

CMD ["bun", "run", "src/server.js"]
