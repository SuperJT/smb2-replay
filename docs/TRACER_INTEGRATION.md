# Integrating SMB Replay with Tracer

This guide covers options for integrating the smbreplay project into the tracer ecosystem while maintaining them as separate repositories.

## Integration Options

### Option 1: Git Submodule (Recommended)

Git submodules allow you to include one repository inside another while keeping them as separate projects with independent histories.

**Pros:**
- Both repos remain independent with their own git history
- Easy to update smbreplay independently
- Clear separation of concerns
- Standard practice for multi-repo projects

**Cons:**
- Submodules require extra git commands to update
- Contributors need to understand submodule workflow

#### Setup Steps

```bash
# From the tracer repository root
cd /home/jtownsen/dev/tracer

# Add smbreplay as a submodule
git submodule add https://bitbucket.ngage.netapp.com/users/jtownsen/repos/smbreplay.git smbreplay

# This creates:
# - .gitmodules file (tracks submodule config)
# - smbreplay/ directory (the submodule)

# Commit the submodule addition
git add .gitmodules smbreplay
git commit -m "feat: Add smbreplay as submodule for SMB replay API"

# To clone tracer with submodules in the future:
git clone --recurse-submodules <tracer-repo-url>

# Or if already cloned without submodules:
git submodule update --init --recursive
```

#### Updating the Submodule

```bash
# Update smbreplay to latest commit
cd smbreplay
git fetch origin
git checkout feature/nextjs-sdk  # or main/master
cd ..
git add smbreplay
git commit -m "chore: Update smbreplay submodule"
```

#### Docker Compose Integration

Update `docker-compose.yml` to build from the submodule:

```yaml
services:
  # ... existing services ...

  smbreplay-api:
    build:
      context: ./smbreplay
      dockerfile: Dockerfile
    container_name: tracer-smbreplay-api
    ports:
      - '3004:3004'
    environment:
      - PORT=3004
      - TRACES_FOLDER=/stingray
    volumes:
      - ${STINGRAY:-~/cases}:/stingray:ro
    healthcheck:
      test: ['CMD', 'wget', '--no-verbose', '--tries=1', '--spider', 'http://localhost:3004/health']
      interval: 10s
      timeout: 5s
      retries: 3
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
```

---

### Option 2: Git Subtree

Git subtree merges one repo into another as a subdirectory, copying the code and history.

**Pros:**
- No special git commands for contributors
- Everything in one repo
- Simpler for CI/CD

**Cons:**
- Harder to push changes back to smbreplay
- Duplicates history in tracer repo
- Can make tracer repo larger

#### Setup Steps

```bash
cd /home/jtownsen/dev/tracer

# Add smbreplay as a remote
git remote add smbreplay https://bitbucket.ngage.netapp.com/users/jtownsen/repos/smbreplay.git

# Fetch the smbreplay history
git fetch smbreplay

# Add as subtree (pulls in the code and history)
git subtree add --prefix=smbreplay smbreplay/feature/nextjs-sdk --squash

# The --squash flag condenses history into a single commit
```

#### Updating from Upstream

```bash
# Pull latest changes from smbreplay
git subtree pull --prefix=smbreplay smbreplay/main --squash
```

---

### Option 3: Separate Repos with Shared Docker Network

Keep repos completely separate and connect via Docker networking.

**Pros:**
- Maximum independence
- Each team can work independently
- Simplest git workflow

**Cons:**
- Need to manage two separate deployments
- Requires Docker registry for production

#### Setup Steps

1. **Push smbreplay to registry** (or build locally):
```bash
cd /home/jtownsen/dev/smbreplay
docker build -t smbreplay-api:latest .

# Optionally push to registry
docker tag smbreplay-api:latest registry.example.com/smbreplay-api:latest
docker push registry.example.com/smbreplay-api:latest
```

2. **Reference in tracer's docker-compose.yml**:
```yaml
services:
  smbreplay-api:
    image: smbreplay-api:latest  # or registry.example.com/smbreplay-api:latest
    # ... rest of config
```

---

### Option 4: Monorepo Migration

Move smbreplay into tracer as a package in the monorepo structure.

**Pros:**
- Single repo to manage
- Atomic commits across both projects
- Shared tooling (CI/CD, linting, etc.)

**Cons:**
- Loses smbreplay's independent history
- Larger, more complex repo
- May not fit existing workflow

#### Setup Steps

```bash
cd /home/jtownsen/dev/tracer

# Create packages directory if not exists
mkdir -p packages

# Copy smbreplay (without .git)
cp -r /home/jtownsen/dev/smbreplay packages/smbreplay
rm -rf packages/smbreplay/.git

# Add to git
git add packages/smbreplay
git commit -m "feat: Add smbreplay package to monorepo"
```

---

## Recommended Approach: Submodule

For your use case, I recommend **Option 1: Git Submodule** because:

1. **Both projects stay independent** - smbreplay can be used standalone or with tracer
2. **Clear ownership** - Each repo has its own maintainers and releases
3. **Flexible updates** - Tracer can pin to specific smbreplay versions
4. **Standard practice** - Well-understood pattern for multi-repo projects

### Quick Start Commands

```bash
# === IN TRACER REPO ===
cd /home/jtownsen/dev/tracer

# 1. Add smbreplay as submodule
git submodule add https://bitbucket.ngage.netapp.com/users/jtownsen/repos/smbreplay.git smbreplay

# 2. Checkout the SDK branch in the submodule
cd smbreplay
git checkout feature/nextjs-sdk
cd ..

# 3. Update docker-compose.yml to include smbreplay-api service
# (Add the service definition from docker-compose.smbreplay.yml)

# 4. Commit everything
git add .
git commit -m "feat: Integrate smbreplay API as submodule

- Add smbreplay as git submodule
- Add smbreplay-api service to docker-compose
- Enables SMB replay functionality via REST API"

# 5. Test the integration
docker-compose up -d smbreplay-api
curl http://localhost:3004/health
```

### TypeScript SDK Integration

To use the TypeScript SDK in tracer's Next.js app:

```bash
# Option A: Local path (for development)
cd /home/jtownsen/dev/tracer/apps/web
npm install ../../smbreplay/sdk

# Option B: Build and link
cd /home/jtownsen/dev/tracer/smbreplay/sdk
npm install && npm run build
npm link

cd /home/jtownsen/dev/tracer/apps/web
npm link @smbreplay/sdk
```

Then in your Next.js code:

```typescript
import { SMBReplayClient } from '@smbreplay/sdk';

const client = new SMBReplayClient({
  baseUrl: process.env.SMBREPLAY_API_URL || 'http://smbreplay-api:3004',
});

// Use in API routes or server components
export async function listSessions() {
  return await client.listSessions();
}
```

---

## Environment Variables

Add these to tracer's environment configuration:

```bash
# .env or docker-compose environment
SMBREPLAY_API_URL=http://smbreplay-api:3004  # Internal Docker network
SMBREPLAY_API_PUBLIC_URL=http://localhost:3004  # External access
```

## Nginx Configuration

If using tracer's nginx proxy, add a location block:

```nginx
# In infrastructure/nginx/nginx.conf
location /api/smbreplay/ {
    proxy_pass http://smbreplay-api:3004/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

This allows accessing the SMB Replay API at `http://tracer.example.com/api/smbreplay/`.
