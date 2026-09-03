# @pathos-labs/dacs-verifier as a container: the HTTP service by default.
# Build from the package directory after `node --import tsx scripts/build-verifier-package.mts`:
#   docker build -t dacs-verifier packages/verifier
# Run:  docker run --rm -p 8787:8787 dacs-verifier                                  (HTTP on 0.0.0.0:8787)
#       docker run --rm -i dacs-verifier dist/packages/verifier/src/mcp.js            (MCP over stdio)
#       docker run --rm -i dacs-verifier dist/packages/verifier/src/cli.js --stdin --offline --json < bundle.json
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY dist ./dist
COPY schemas ./schemas
COPY provenance.json README.md LICENSE NOTICE ./
ENV DACS_VERIFIER_HOST=0.0.0.0 DACS_VERIFIER_PORT=8787 NODE_ENV=production
EXPOSE 8787
USER node
ENTRYPOINT ["node"]
CMD ["dist/packages/verifier/src/http.js"]
