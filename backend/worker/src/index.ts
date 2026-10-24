import https from 'https';
import http from 'http';
import dns from 'dns/promises';
import tls from 'tls';
import { URL } from 'url';

/**
 * Sentinel Pro Defensive Security Worker
 * Implements headless defensive checks with strict authorization verification and SSRF protection.
 */

export interface ScopeRule {
    hostname: string;
    wildcardAllowed: boolean;
    allowedPorts: number[];
    pathPrefix?: string;
}

export interface AuthorizationContext {
    authorized: boolean;
    validTo: string;
    allowedScopes: ScopeRule[];
}

export class DefensiveWorker {
    private authContext: AuthorizationContext;

    constructor(authContext: AuthorizationContext) {
        this.authContext = authContext;
    }

    /**
     * Scope enforcement check - MUST pass before any socket is opened.
     */
    public async validateScope(targetUrl: string): Promise<{ valid: boolean; reason?: string; host?: string; port?: number }> {
        if (!this.authContext.authorized) {
            return { valid: false, reason: 'No written Rules of Engagement (ROA) authorization' };
        }

        const now = new Date();
        if (now > new Date(this.authContext.validTo)) {
            return { valid: false, reason: 'Authorization window has expired' };
        }

        let parsed: URL;
        try {
            parsed = new URL(targetUrl);
        } catch (e) {
            return { valid: false, reason: 'Invalid URL format' };
        }

        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return { valid: false, reason: 'Protocol must be HTTP or HTTPS' };
        }

        const host = parsed.hostname.toLowerCase();
        const port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);

        // Disallow loopback / internal / cloud metadata hosts
        const blockedHosts = [
            'localhost',
            '127.0.0.1',
            '::1',
            '169.254.169.254',
            'metadata.google.internal',
            'instance-data'
        ];
        if (blockedHosts.includes(host)) {
            return { valid: false, reason: 'Prohibited internal/loopback or cloud metadata destination' };
        }

        // Match against approved scope registry
        const matched = this.authContext.allowedScopes.some(rule => {
            const ruleHost = rule.hostname.toLowerCase();
            const hostMatches = rule.wildcardAllowed
                ? (host === ruleHost || host.endsWith(`.${ruleHost}`))
                : (host === ruleHost);
            const portMatches = rule.allowedPorts.includes(port);
            const pathMatches = !rule.pathPrefix || parsed.pathname.startsWith(rule.pathPrefix);
            return hostMatches && portMatches && pathMatches;
        });

        if (!matched) {
            return { valid: false, reason: `Host ${host}:${port} is NOT in authorized engagement scopes`, host, port };
        }

        // DNS resolution check: verify resolved IP is not private/loopback/SSRF target
        try {
            const addresses = await dns.resolve(host);
            for (const addr of addresses) {
                if (this.isProhibitedIp(addr)) {
                    return { valid: false, reason: `Host resolves to prohibited internal address: ${addr}`, host, port };
                }
            }
        } catch (err: any) {
            return { valid: false, reason: `DNS resolution failed: ${err.message}`, host, port };
        }

        return { valid: true, host, port };
    }

    /**
     * Checks if IP address belongs to loopback, private RFC 1918, link-local, or cloud metadata.
     */
    public isProhibitedIp(ip: string): boolean {
        if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') return true;
        if (ip === '169.254.169.254') return true;

        const parts = ip.split('.').map(p => parseInt(p, 10));
        if (parts.length === 4 && !parts.some(isNaN)) {
            // 10.0.0.0/8
            if (parts[0] === 10) return true;
            // 172.16.0.0/12
            if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
            // 192.168.0.0/16
            if (parts[0] === 192 && parts[1] === 168) return true;
            // 127.0.0.0/8
            if (parts[0] === 127) return true;
            // 169.254.0.0/16
            if (parts[0] === 169 && parts[1] === 254) return true;
            // 100.64.0.0/10 (CGNAT)
            if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
        }

        // IPv6 ULA or Link-Local
        const lower = ip.toLowerCase();
        if (lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80:')) return true;

        return false;
    }

    /**
     * Conducts defensive TLS audit.
     */
    public async inspectTls(hostname: string, port: number = 443): Promise<any> {
        return new Promise((resolve) => {
            const socket = tls.connect(port, hostname, { servername: hostname, minVersion: 'TLSv1.2' }, () => {
                const cert = socket.getPeerCertificate();
                const cipher = socket.getCipher();
                const protocol = socket.getProtocol();

                socket.end();
                resolve({
                    protocol,
                    cipher: cipher.name,
                    validTo: cert.valid_to,
                    issuer: cert.issuer?.O || cert.issuer?.CN,
                    subject: cert.subject?.CN,
                    sans: cert.subjectaltname
                });
            });

            socket.on('error', (err) => {
                resolve({ error: err.message });
            });
            socket.setTimeout(6000, () => {
                socket.destroy();
                resolve({ error: 'TLS Handshake Timeout' });
            });
        });
    }

    /**
     * Conducts HTTP security header inspection.
     */
    public async inspectHeaders(targetUrl: string): Promise<Record<string, string>> {
        return new Promise((resolve, reject) => {
            const parsed = new URL(targetUrl);
            const client = parsed.protocol === 'https:' ? https : http;

            const req = client.request(targetUrl, {
                method: 'HEAD',
                headers: { 'User-Agent': 'Sentinel-Pro-Worker/1.0 (Defensive Security Audit)' },
                timeout: 6000
            }, (res) => {
                const headers: Record<string, string> = {};
                for (const [key, val] of Object.entries(res.headers)) {
                    if (val) headers[key.toLowerCase()] = Array.isArray(val) ? val.join('; ') : val;
                }
                resolve(headers);
            });

            req.on('error', reject);
            req.on('timeout', () => req.destroy(new Error('Connection timeout')));
            req.end();
        });
    }
}

// Standalone runner / healthcheck server if invoked directly
if (require.main === module) {
    const port = parseInt(process.env.WORKER_PORT || '8080', 10);
    const server = http.createServer((req, res) => {
        if (req.url === '/health' || req.url === '/') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'ok', service: 'sentinel-pro-worker', timestamp: new Date().toISOString() }));
            return;
        }
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not Found' }));
    });

    server.listen(port, () => {
        console.log(`[Sentinel Pro Worker] Defensive assessment daemon listening on port ${port}`);
    });
}
