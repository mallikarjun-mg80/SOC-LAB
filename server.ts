import express from 'express';
import path from 'path';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';

const app = express();
const PORT = 3000;

app.use(express.json());

// In-memory simulation state with seeded data
interface SessionUser {
  id: string;
  username: string;
  role: 'SOC Analyst' | 'SOC Admin';
  name: string;
  token: string;
}

const activeSessions: Map<string, SessionUser> = new Map();

// Helper for secure password hashing using Node crypto PBKDF2
function hashPassword(password: string, salt: string = 'soc-sentinel-salt-2026'): string {
  return crypto.pbkdf2Sync(password, salt, 1000, 32, 'sha256').toString('hex');
}

const REGISTERED_CREDENTIALS: Record<string, { hash: string; role: 'SOC Analyst' | 'SOC Admin'; name: string; id: string }> = {
  analyst: {
    hash: hashPassword('Analyst@123'),
    role: 'SOC Analyst',
    name: 'Alex Vance (Junior SOC Analyst)',
    id: 'usr-1'
  },
  admin: {
    hash: hashPassword('Admin@123'),
    role: 'SOC Admin',
    name: 'Sarah Connor (Lead Incident Commander)',
    id: 'usr-2'
  }
};

// API: Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    system: 'SOC Sentinel Lab Engine',
    timestamp: new Date().toISOString(),
    threatLevel: 'ELEVATED (DEFCON 3)'
  });
});

// API: Auth Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const userRecord = REGISTERED_CREDENTIALS[username.toLowerCase().trim()];
  if (!userRecord) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const inputHash = hashPassword(password);
  if (inputHash !== userRecord.hash) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const token = crypto.randomBytes(24).toString('hex');
  const sessionUser: SessionUser = {
    id: userRecord.id,
    username: username.toLowerCase().trim(),
    role: userRecord.role,
    name: userRecord.name,
    token
  };
  activeSessions.set(token, sessionUser);

  res.json({
    token,
    user: {
      id: sessionUser.id,
      username: sessionUser.username,
      role: sessionUser.role,
      name: sessionUser.name
    }
  });
});

// API: Auth Logout
app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    activeSessions.delete(token);
  }
  res.json({ success: true, message: 'Logged out successfully' });
});

// API: Auth Me
app.get('/api/auth/me', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = authHeader.substring(7);
  const sessionUser = activeSessions.get(token);
  if (!sessionUser) {
    return res.status(401).json({ error: 'Session expired or invalid' });
  }
  res.json({ user: sessionUser });
});

// Real-time Event Stream (SSE) for live simulation updates
app.get('/api/events/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  // Send initial connection ping
  res.write(`data: ${JSON.stringify({ type: 'PING', message: 'SSE Stream connected', timestamp: new Date().toISOString() })}\n\n`);

  const eventInterval = setInterval(() => {
    const sampleEvents = [
      { type: 'EVENT_DNS', message: 'DNS Query: api.internal.corp A record resolved (192.168.10.20)', host: 'DNS01', proto: 'DNS' },
      { type: 'EVENT_AUTH', message: 'Event 4624: Successful logon for svc_telemetry on DC01', host: 'DC01', proto: 'Kerberos' },
      { type: 'EVENT_NET', message: 'HTTPS outbound session 192.168.10.15:54201 -> 142.250.190.46:443 [ESTABLISHED]', host: 'EDGE-FW01', proto: 'HTTPS' },
      { type: 'EVENT_PROCESS', message: 'Process spawned: svchost.exe (PID 840) Network Service', host: 'CLIENT02', proto: 'LOCAL' }
    ];
    const ev = sampleEvents[Math.floor(Math.random() * sampleEvents.length)];
    res.write(`data: ${JSON.stringify({ ...ev, timestamp: new Date().toLocaleTimeString() })}\n\n`);
  }, 4000);

  req.on('close', () => {
    clearInterval(eventInterval);
  });
});

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SOC Sentinel Lab] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
