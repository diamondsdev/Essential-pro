import https from 'https';
import http from 'http';
import dns from 'dns/promises';
import tls from 'tls';
import { URL } from 'url';

/**
 * Sentinel Pro Defensive Security Worker
 * Implements headless defensive checks with strict authorization verification.
 */

interface ScopeRule {
    hostname: string;
    wildcardAllowed: boolean;
    allowedPorts: number[];
}

interface AuthorizationContext {
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
    public async validateScope(targetUrl: string): Promise<{ valid: boolean; reason?: string; host?: string }> {
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

        const host = parsed.hostname.toLowerCase();
        const port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);

        // Disallow private / local destinations
        if (['localhost', '127.0.0.1', '::1', '169.254.169.254'].includes(host)) {
            return { valid: false, reason: 'Prohibited internal/loopback destination' };
        }

        // Match against approved scope registry
        const matched = this.authContext.allowedScopes.some(rule => {
            const ruleHost = rule.hostname.toLowerCase();
            const hostMatches = rule.wildcardAllowed
                ? (host === ruleHost || host.endsWith(`.${ruleHost}`))
                : (host === ruleHost);
            return hostMatches && rule.allowedPorts.includes(port);
        });

        if (!matched) {
            return { valid: false, reason: `Host ${host}:${port} is NOT in authorized engagement scopes`, host };
        }

        return { valid: true, host };
    }

    /**
     * Conducts defensive TLS audit.
     */
    public async inspectTls(hostname: string): Promise<any> {
        return new Promise((resolve) => {
            const socket = tls.connect(443, hostname, { servername: hostname, minVersion: 'TLSv1.2' }, () => {
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
                headers: { 'User-Agent': 'Sentinel-Pro-Worker/1.0' },
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
