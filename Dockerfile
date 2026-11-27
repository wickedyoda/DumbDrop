# Base stage for shared configurations
# node:24-alpine is used deliberately: it matches the Node 24 toolchain the CI
# verify job runs, ships Alpine 3.24.4 (libexpat fixes) and npm 11.x, which
# removes the vulnerable packages bundled inside npm 10.9.x (pacote, sigstore,
# brace-expansion, ip-address).
FROM node:24-alpine AS base

# Install python and create virtual environment with minimal dependencies
RUN apk add --no-cache python3 py3-pip && \
    python3 -m venv /opt/venv && \
    rm -rf /var/cache/apk/*

# Activate virtual environment and install apprise (pinned for reproducibility).
# pip/setuptools are refreshed first: the venv seed carried setuptools 70.3.0
# (CVE-2025-47273) and apprise's older dependency set pulled urllib3 2.7.0,
# msgpack 1.1.2 and oauthlib 4.0.0, all of which are flagged.
RUN . /opt/venv/bin/activate && \
    pip install --no-cache-dir -U pip setuptools wheel && \
    pip install --no-cache-dir "apprise==2.3.0" && \
    # build-only packages are not needed by the apprise CLI at runtime; removing
    # them keeps the image free of their (stale) metadata
    pip uninstall -y setuptools wheel && \
    find /opt/venv -type d -name "__pycache__" -exec rm -r {} +

# Add virtual environment to PATH
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /usr/src/app

# Dependencies stage
FROM base AS deps

COPY package*.json ./
RUN npm ci --omit=dev && \
    # Remove npm cache
    npm cache clean --force

# Development stage
FROM deps AS development
ENV NODE_ENV=development

# Install dev dependencies
RUN npm install && \
    npm cache clean --force

# Create upload and logs directories
RUN mkdir -p uploads /logs

# Copy source with specific paths to avoid unnecessary files
# (the previous paths __tests__/, dev/, .eslintrc.json and .eslintignore do not
# exist in this repository, which made the development target unbuildable)
COPY src/ ./src/
COPY public/ ./public/
COPY test/ ./test/
COPY eslint.config.js .prettierrc ./

# Expose port
EXPOSE 3000

CMD ["npm", "run", "dev"]

# Production stage
FROM deps AS production
ENV NODE_ENV=production

# The runtime needs only the node binary and the app's node_modules. The npm CLI
# bundle is build-time tooling and was the source of every HIGH finding left in
# this image after the dependency refresh (npm 11.19.1 vendors undici 6.28.0 and
# brace-expansion 5.0.9 at /usr/local/lib/node_modules/npm/node_modules/).
# Dropping it also removes ~18 MB. CMD therefore runs node directly instead of
# `npm start`, which is the same entry point (package.json "start": "node src/server.js").
RUN rm -rf /usr/local/lib/node_modules/npm \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
           /opt/venv/lib/python3.*/site-packages/pip \
           /opt/venv/lib/python3.*/site-packages/pip-*.dist-info \
           /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.* \
           /usr/lib/python3.*/site-packages/pip \
           /usr/lib/python3.*/site-packages/pip-*.dist-info \
           /usr/bin/pip /usr/bin/pip3 /usr/bin/pip3.*
# (the pip removal is deliberate: pip's vendored SBOM, pip/_vendor/bom.cdx.json,
#  advertises setuptools 70.3.0 which trivy reports as an installed HIGH finding
#  even though no setuptools distribution exists in the image)

# Create upload and logs directories
RUN mkdir -p uploads /logs

# Copy only necessary source files
COPY src/ ./src/
COPY public/ ./public/

# Expose port
EXPOSE 3000

CMD ["node", "src/server.js"]
