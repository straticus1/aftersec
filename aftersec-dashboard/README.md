# AfterSec Dashboard

Next.js 16 dashboard for AfterSec enterprise security management platform.

## Features

- ✅ Server-side authentication with NextAuth.js v5
- ✅ Protected routes with middleware
- ✅ JWT-based sessions
- ✅ Beautiful cyberpunk-themed UI with Tailwind CSS v4
- ✅ Real-time endpoint monitoring
- ✅ Scan history and analysis
- ✅ Responsive design

## Getting Started

### Prerequisites

- Node.js 18+
- AfterSec server running (default: http://localhost:8080)

### Installation

```bash
# Install dependencies
npm install

# Copy environment variables
cp .env.example .env.local

# Generate NextAuth secret
openssl rand -base64 32

# Update .env.local with the generated secret
# NEXTAUTH_SECRET=<your-generated-secret>
```

### Development

```bash
# Start development server
npm run dev

# Open browser
open http://localhost:3000
```

### Build for Production

```bash
# Build the application
npm run build

# Start production server
npm start
```

## Authentication

The dashboard uses NextAuth.js v5 with credentials provider.

### Login Flow

1. User enters email and password
2. Credentials are sent to AfterSec API `/api/v1/auth/login`
3. API returns access token and user info
4. NextAuth creates JWT session
5. User is redirected to dashboard

### Protected Routes

All routes except `/login` require authentication. The middleware automatically redirects unauthenticated users to the login page.

### Session Management

- Sessions are JWT-based
- Default session duration: 24 hours
- Session includes: user ID, email, name, role, organization ID, access token

## Environment Variables

Create `.env.local` file:

```env
# API Configuration
NEXT_PUBLIC_API_URL=http://localhost:8080/api/v1

# NextAuth Configuration
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=your-secret-here

# Environment
NODE_ENV=development
```

## Project Structure

```
aftersec-dashboard/
├── src/
│   ├── app/
│   │   ├── api/auth/[...nextauth]/  # NextAuth API routes
│   │   ├── endpoints/               # Endpoints page
│   │   ├── login/                   # Login page
│   │   ├── scans/                   # Scans page
│   │   ├── layout.tsx               # Root layout
│   │   └── page.tsx                 # Dashboard home
│   ├── components/
│   │   ├── Header.tsx               # Navigation header
│   │   └── Providers.tsx            # Session provider wrapper
│   ├── lib/
│   │   └── api.ts                   # API client
│   ├── types/
│   │   └── next-auth.d.ts           # NextAuth type extensions
│   ├── auth.config.ts               # NextAuth configuration
│   ├── auth.ts                      # NextAuth instance
│   └── middleware.ts                # Route protection
├── .env.example                     # Environment template
├── package.json
└── README.md
```

## API Integration

The dashboard communicates with the AfterSec server via REST API:

### Endpoints

- `GET /api/v1/health` - Health check
- `POST /api/v1/auth/login` - User authentication
- `GET /api/v1/organizations` - List organizations
- `GET /api/v1/endpoints` - List endpoints
- `GET /api/v1/scans` - List scans

### Authenticated Requests

All API requests (except login) include the JWT access token:

```typescript
const response = await fetch(`${API_URL}/endpoints`, {
  headers: {
    'Authorization': `Bearer ${session.accessToken}`,
  },
});
```

## Development Notes

### Adding New Pages

1. Create page in `src/app/`
2. Add navigation link to `Header.tsx`
3. Page is automatically protected by middleware

### API Client

Use the centralized API client in `src/lib/api.ts`:

```typescript
import { getEndpoints } from '@/lib/api';

const endpoints = await getEndpoints(accessToken);
```

### Styling

The dashboard uses Tailwind CSS v4 with a cyberpunk-inspired design:

- Background: `bg-slate-950`
- Primary gradient: `from-indigo-400 to-cyan-400`
- Borders: `border-slate-800`
- Glass effect: `bg-slate-900/40 backdrop-blur-xl`

## Troubleshooting

### "Invalid credentials" error

- Verify AfterSec server is running
- Check `NEXT_PUBLIC_API_URL` in `.env.local`
- Ensure `/api/v1/auth/login` endpoint exists

### Session not persisting

- Check `NEXTAUTH_SECRET` is set
- Verify `NEXTAUTH_URL` matches your domain
- Clear browser cookies and try again

### Build errors

```bash
# Clear Next.js cache
rm -rf .next

# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install

# Rebuild
npm run build
```

## Production Deployment

### Docker

The dashboard is included in the main Docker Compose stack:

```bash
docker-compose up -d dashboard
```

### Environment Variables (Production)

```env
NEXT_PUBLIC_API_URL=https://api.aftersec.example.com/api/v1
NEXTAUTH_URL=https://dashboard.aftersec.example.com
NEXTAUTH_SECRET=<production-secret>
NODE_ENV=production
```

### Vercel / Netlify

1. Connect repository
2. Set environment variables
3. Deploy

## License

Proprietary - AfterSec Enterprise
