# AfterSec Dashboard Architecture

## Overview

The dashboard is a **Next.js 16 (React 19)** web application running in its own Docker container, written in **TypeScript**.

## Tech Stack

```
┌─────────────────────────────────────────────────────┐
│          Dashboard Container (Node.js)              │
│                                                     │
│  Technology: Next.js 16 + React 19 + TypeScript    │
│  Runtime: Node.js 20 Alpine                        │
│  Port: 3000                                        │
│                                                     │
│  ┌─────────────────────────────────────────────┐  │
│  │  Frontend Framework                          │  │
│  │  • Next.js 16.2.1 (App Router)              │  │
│  │  • React 19.2.4                             │  │
│  │  • TypeScript 5                             │  │
│  └─────────────────────────────────────────────┘  │
│                                                     │
│  ┌─────────────────────────────────────────────┐  │
│  │  UI Libraries                                │  │
│  │  • TailwindCSS 4 (styling)                  │  │
│  │  • Lucide React (icons)                     │  │
│  │  • Recharts (data visualization)            │  │
│  │  • Monaco Editor (code editing)             │  │
│  └─────────────────────────────────────────────┘  │
│                                                     │
│  ┌─────────────────────────────────────────────┐  │
│  │  Authentication                              │  │
│  │  • NextAuth 5.0 (beta)                      │  │
│  │  • JWT tokens from Go API                   │  │
│  └─────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
                      ↓ HTTP/REST
┌─────────────────────────────────────────────────────┐
│       API Server Container (Go)                      │
│                                                     │
│  Technology: Go 1.22+                               │
│  Port: 8080 (REST), 9090 (gRPC)                    │
│                                                     │
│  • /api/v1/organizations                           │
│  • /api/v1/endpoints                               │
│  • /api/v1/scans                                   │
│  • /api/v1/darkweb/alerts                          │
│  • /api/v1/ai/budget                               │
└─────────────────────────────────────────────────────┘
```

---

## Docker Container Details

### Dashboard Container (Node.js)

**Dockerfile:** `Dockerfile.dashboard`

```dockerfile
FROM node:20-alpine AS base

# Build dependencies
FROM base AS deps
WORKDIR /app
COPY aftersec-dashboard/package.json package-lock.json ./
RUN npm ci

# Build application
FROM base AS builder
WORKDIR /app
COPY aftersec-dashboard .
COPY --from=deps /app/node_modules ./node_modules
RUN npm run build

# Production runtime
FROM base AS runner
WORKDIR /app
ENV NODE_ENV production
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

EXPOSE 3000
CMD ["npm", "start"]
```

**Key Points:**
- **Multi-stage build** - Optimized for small image size
- **Node.js 20 Alpine** - Lightweight base image (~150MB final)
- **Production optimizations** - Next.js static optimization + SSR
- **Port 3000** - Standard Next.js port

---

## Communication Flow

```
┌──────────────┐
│   Browser    │
│              │
│  User at     │
│  localhost   │
│  :3000       │
└──────┬───────┘
       │
       │ HTTPS (production)
       │ HTTP (dev)
       │
       ▼
┌─────────────────────────────────────────────┐
│  Dashboard Container (Next.js/React)        │
│                                             │
│  • Renders UI (React components)           │
│  • Client-side routing (Next.js App Router)│
│  • State management (React hooks)          │
│                                             │
│  Pages:                                     │
│  • /          - Home/Overview               │
│  • /settings  - Configuration               │
│  • /bandit    - Python Security             │
│  • /endpoint-ai - On-device AI              │
│  • /signatures - Detection Rules            │
└─────────────┬───────────────────────────────┘
              │
              │ fetch() API calls
              │ Authorization: Bearer {jwt_token}
              │
              ▼
┌─────────────────────────────────────────────┐
│  API Server Container (Go)                   │
│                                             │
│  REST API on port 8080:                     │
│  • JWT middleware (authentication)          │
│  • Tier middleware (license enforcement)    │
│  • Database queries (PostgreSQL)            │
│  • AI analysis orchestration                │
│  • Dark web intelligence queries            │
└─────────────┬───────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────┐
│  PostgreSQL Database                         │
│                                             │
│  • Organizations                            │
│  • Endpoints                                │
│  • Scans                                    │
│  • Events                                   │
└─────────────────────────────────────────────┘
```

---

## Development vs Production

### Development Mode

```bash
# Terminal 1: Start Go API server
cd /Users/ryan/development/experiments-no-claude/go/aftersec
./bin/aftersec-server

# Terminal 2: Start Next.js dev server
cd aftersec-dashboard
npm run dev
```

**Features:**
- Hot Module Replacement (HMR) - instant UI updates
- Fast Refresh - preserves React state during edits
- Source maps - debugging in browser
- No Docker needed
- API at http://localhost:8080
- Dashboard at http://localhost:3000

### Production Mode (Docker)

```bash
# Start full stack with Docker Compose
docker-compose up -d

# Or production config
docker-compose -f docker-compose.production.yml up -d
```

**What happens:**
1. **PostgreSQL** starts (port 5432)
2. **API Server** builds from Go source, waits for DB (port 8080, 9090)
3. **Dashboard** builds Next.js production bundle (port 3000)
4. Cloudflare Tunnel exposes to internet

---

## Package.json Scripts

```json
{
  "scripts": {
    "dev": "next dev",           // Development server with HMR
    "build": "next build",       // Production build (SSR + static)
    "start": "next start",       // Production server
    "lint": "eslint"             // Code linting
  }
}
```

---

## Key Technologies Explained

### 1. Next.js 16 (React Framework)

**Why Next.js instead of plain React?**
- **Server-Side Rendering (SSR)** - Fast initial page loads
- **API Routes** - Can host API endpoints if needed (not used, Go handles API)
- **App Router** - Modern file-based routing
- **Image Optimization** - Automatic image resizing
- **Built-in TypeScript** - Type safety out of the box

**File Structure:**
```
aftersec-dashboard/src/
├── app/                    # Next.js App Router pages
│   ├── page.tsx           # Home page (/)
│   ├── settings/page.tsx  # Settings page (/settings)
│   ├── bandit/page.tsx    # Bandit page (/bandit)
│   └── layout.tsx         # Root layout
├── components/             # React components
│   ├── Sidebar.tsx
│   ├── TierStatusBanner.tsx
│   └── ...
├── lib/                    # Utilities
│   └── hooks/             # Custom React hooks
└── types/                  # TypeScript types
```

### 2. React 19 (UI Library)

**Latest features:**
- React Server Components (RSC)
- Automatic batching
- Transitions API
- useOptimistic hook

### 3. TypeScript (Type Safety)

All dashboard code is **fully typed**:
```typescript
interface TierInfo {
  current_tier: string
  tier_level: number
  ai_budget: {
    daily_limit_usd: number
    monthly_limit_usd: number
    // ...
  }
}
```

Benefits:
- Catch errors at compile time
- IntelliSense in VS Code
- Refactoring safety
- API contract enforcement

### 4. TailwindCSS 4 (Styling)

Utility-first CSS framework:
```tsx
<div className="bg-gray-900 border border-cyan-500 rounded-lg p-4">
  <h1 className="text-2xl font-bold text-white">Title</h1>
</div>
```

**Why Tailwind?**
- No CSS files to manage
- Consistent design system
- Dark mode built-in
- Responsive utilities
- Tree-shaking (unused styles removed)

### 5. Recharts (Data Visualization)

React charting library for security dashboards:
```tsx
<LineChart data={scanHistory}>
  <XAxis dataKey="timestamp" />
  <YAxis />
  <Line dataKey="threatScore" stroke="#00D9FF" />
</LineChart>
```

### 6. NextAuth 5 (Authentication)

Handles JWT authentication with Go API:
```typescript
// Middleware checks JWT on protected routes
export { auth as middleware } from "@/auth"
```

**Flow:**
1. User logs in → Go API returns JWT
2. Dashboard stores JWT in localStorage
3. All API requests include: `Authorization: Bearer {token}`
4. NextAuth validates and refreshes tokens

---

## How Data Flows

### Example: Viewing AI Budget

```typescript
// 1. React component on dashboard
export default function TierStatusBanner({ orgId }: { orgId: string }) {
  const [tierInfo, setTierInfo] = useState<TierInfo | null>(null)

  useEffect(() => {
    // 2. Fetch from Go API
    fetch(`/api/v1/organizations/tier?org_id=${orgId}`, {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('jwt_token')}`
      }
    })
    .then(res => res.json())
    .then(data => setTierInfo(data)) // 3. Update React state
  }, [orgId])

  // 4. Render UI with data
  return (
    <div>
      <span>{tierInfo?.current_tier}</span>
      <div>Budget: ${tierInfo?.ai_budget.monthly_used_usd}</div>
    </div>
  )
}
```

**What happens:**
1. React component mounts
2. `fetch()` sends HTTP GET to Go API (port 8080)
3. Go API checks JWT, queries PostgreSQL
4. Go returns JSON response
5. React updates state
6. UI re-renders with data

---

## Environment Variables

### Dashboard (.env)

```bash
# API endpoint (internal Docker network)
NEXT_PUBLIC_API_URL=http://server:8080/api/v1

# Or for local development
NEXT_PUBLIC_API_URL=http://localhost:8080/api/v1

# NextAuth
NEXTAUTH_SECRET=your-secret-here
NEXTAUTH_URL=http://localhost:3000
```

**Note:** `NEXT_PUBLIC_*` variables are exposed to browser (public)

### API Server (.env)

```bash
# Database
DATABASE_URL=postgres://...

# JWT Secret (shared with dashboard)
JWT_SECRET=your-jwt-secret

# LLM API Keys
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=...

# Dark Web
DARKAPI_API_KEY=...
```

---

## Deployment Architecture

### Local Development
```
[Browser] → http://localhost:3000 → Next.js Dev Server (Node.js)
                                    ↓
                          http://localhost:8080 → Go API Server
                                                  ↓
                                          PostgreSQL (Docker)
```

### Production (Docker Compose)
```
[Browser] → https://dashboard.yourdomain.com → Cloudflare Tunnel
                                               ↓
                                    Docker: dashboard:3000 (Next.js)
                                               ↓
                                    Docker: server:8080 (Go API)
                                               ↓
                                    Docker: postgres:5432
```

### Production (OCI + Cloudflare)
```
[Internet] → Cloudflare Edge → Cloudflare Tunnel → OCI VM
                                                   ↓
                                    Docker Swarm / Kubernetes
                                    ├── dashboard × 2 replicas
                                    ├── api-server × 3 replicas
                                    ├── postgres-primary
                                    ├── postgres-replica
                                    └── redis
```

---

## Build Process

### Docker Build

When you run `docker-compose up`:

**Step 1: Build stage**
```bash
# Install dependencies
npm ci  # Clean install from package-lock.json

# Build Next.js
npm run build
# Creates .next/ directory with:
# • Pre-rendered pages (SSG)
# • Server bundles (SSR)
# • Static assets
# • Optimized JavaScript bundles
```

**Step 2: Runtime stage**
```bash
# Start production server
npm start
# Runs: next start
# Serves pre-built .next/ directory
```

### Build Output

```
.next/
├── static/                 # Static assets (hashed for caching)
│   ├── chunks/            # JavaScript bundles
│   └── css/               # CSS files
├── server/                 # Server-side code
│   ├── app/               # SSR page handlers
│   └── pages/             # API routes (if any)
└── cache/                  # Build cache
```

---

## Performance Optimizations

### 1. Static Site Generation (SSG)
Pages that don't need real-time data are pre-rendered at build time:
```typescript
// This page is pre-rendered as static HTML
export default function AboutPage() {
  return <div>About AfterSec</div>
}
```

### 2. Server-Side Rendering (SSR)
Pages with dynamic data are rendered on the server:
```typescript
// This page fetches data on every request
export default async function DashboardPage() {
  const data = await fetch('http://server:8080/api/v1/scans')
  return <Dashboard data={data} />
}
```

### 3. Client-Side Rendering (CSR)
Real-time updates happen in the browser:
```typescript
// useEffect runs in browser, updates UI without page reload
useEffect(() => {
  const interval = setInterval(fetchLatestScans, 5000)
  return () => clearInterval(interval)
}, [])
```

### 4. Code Splitting
Next.js automatically splits code per route:
- `/settings` page only loads settings code
- `/bandit` page only loads bandit code
- Shared components are in a separate chunk

### 5. Image Optimization
```tsx
import Image from 'next/image'

<Image src="/logo.png" width={200} height={50} />
// Automatically optimized, lazy-loaded, responsive
```

---

## Security Considerations

### 1. JWT Storage
```typescript
// Stored in localStorage (accessible to JavaScript)
localStorage.setItem('jwt_token', token)

// Sent with every API request
headers: { 'Authorization': `Bearer ${token}` }
```

**Trade-off:** Vulnerable to XSS, but enables SPA architecture

**Better alternative (TODO):**
- HttpOnly cookies (immune to XSS)
- Requires CORS configuration

### 2. CSRF Protection
NextAuth handles CSRF tokens automatically

### 3. Content Security Policy (CSP)
```tsx
// next.config.ts
const cspHeader = `
  default-src 'self';
  script-src 'self' 'unsafe-eval';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self' http://localhost:8080;
`
```

---

## Common Development Tasks

### Adding a New Page

```bash
# Create new page file
touch aftersec-dashboard/src/app/my-page/page.tsx
```

```tsx
// aftersec-dashboard/src/app/my-page/page.tsx
export default function MyPage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold">My New Page</h1>
    </div>
  )
}
```

Automatically available at: http://localhost:3000/my-page

### Adding a New Component

```tsx
// aftersec-dashboard/src/components/MyComponent.tsx
export default function MyComponent({ data }: { data: string }) {
  return <div>{data}</div>
}
```

### Calling Go API

```typescript
async function fetchData() {
  const response = await fetch('/api/v1/scans', {
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('jwt_token')}`
    }
  })

  if (!response.ok) {
    throw new Error('Failed to fetch')
  }

  return response.json()
}
```

---

## Troubleshooting

### Dashboard won't start in Docker

```bash
# Check logs
docker-compose logs dashboard

# Common issues:
# 1. Build failed - check package.json syntax
# 2. Port conflict - change port in docker-compose.yml
# 3. API unreachable - verify server container is running
```

### Hot reload not working (dev mode)

```bash
# Next.js sometimes needs restart
# Ctrl+C and re-run:
npm run dev
```

### TypeScript errors

```bash
# Check for type errors
npm run build

# Fix with:
# 1. Update type definitions
# 2. Add type annotations
# 3. Use 'any' as last resort (not recommended)
```

### API calls failing (CORS)

When dashboard (localhost:3000) calls API (localhost:8080):
```go
// Go API needs CORS headers
w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
```

---

## Summary

**The Dashboard Is:**
- ✅ **Next.js 16** - React framework with SSR
- ✅ **TypeScript** - Fully typed
- ✅ **Node.js 20** - JavaScript runtime
- ✅ **Docker Container** - Separate from Go API
- ✅ **Port 3000** - Standard Next.js port
- ✅ **REST Client** - Calls Go API on port 8080

**The Dashboard Is NOT:**
- ❌ Python (that's Bandit, a different tool)
- ❌ Embedded in Go binary
- ❌ Static HTML files
- ❌ PHP, Ruby, or Java

**Simple Answer:**
> The dashboard is a **Node.js (JavaScript/TypeScript)** web application using **Next.js + React**, running in its own Docker container on **port 3000**. It talks to your **Go API server** on port 8080 via REST API calls.

