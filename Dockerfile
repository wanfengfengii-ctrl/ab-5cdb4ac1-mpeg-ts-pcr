FROM node:20-slim

WORKDIR /app

# Zero runtime dependencies; ship sources, tests and build scripts so the
# one-shot verify service can test, build and smoke-test inside the image.
COPY package.json ./
COPY src ./src
COPY test ./test
COPY scripts ./scripts

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0

EXPOSE 8080

HEALTHCHECK --interval=2s --timeout=3s --start-period=2s --retries=15 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "src/server.mjs"]
