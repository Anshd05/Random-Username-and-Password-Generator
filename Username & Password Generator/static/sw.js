/**
 * SERVICE WORKER — Offline PWA Support
 * Enables CryptoGen to work offline with client-side crypto generation.
 * When server is unreachable, uses pure JavaScript WebCrypto API.
 */

'use strict';

const CACHE_VERSION = 'cryptogen-v1.0.0';
const STATIC_CACHE = `${CACHE_VERSION}-static`;
const RUNTIME_CACHE = `${CACHE_VERSION}-runtime`;

// Resources to pre-cache for offline use
const PRECACHE_URLS = [
    '/',
    '/templates/index.html',
    '/manifest.json',
];

/**
 * OFFLINE-CAPABLE CLIENT-SIDE GENERATOR
 * Full-featured password generator using ONLY Web Crypto API.
 * Activated when server is unreachable.
 * Provides identical security guarantees via browser's CSPRNG.
 */
class OfflineCryptoGen {
    static CHARSETS = {
        lowercase: 'abcdefghijklmnopqrstuvwxyz',
        uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        digits: '0123456789',
        special: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    };
    
    /**
     * Pure JavaScript random number in [0, max) using Web Crypto API.
     * Uses rejection sampling to eliminate modulo bias.
     */
    static secureRandom(max) {
        const range = 2**32;
        const limit = range - (range % max);
        
        let value;
        do {
            const buf = new Uint32Array(1);
            crypto.getRandomValues(buf);
            value = buf[0];
        } while (value >= limit);
        
        return value % max;
    }
    
    /**
     * Cryptographically secure array shuffle (Fisher-Yates)
     */
    static secureShuffle(array) {
        const arr = [...array];
        for (let i = arr.length - 1; i > 0; i--) {
            const j = this.secureRandom(i + 1);
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr;
    }
    
    /**
     * Generate a secure password entirely client-side
     */
    static generate({
        length = 24,
        useLowercase = true,
        useUppercase = true,
        useDigits = true,
        useSpecial = true,
        excludeAmbiguous = false,
    } = {}) {
        const AMBIGUOUS = new Set('Il1O0o');
        
        let pool = '';
        const required = [];
        
        const addCharset = (charsetName, charsetStr, minRequired = 1) => {
            let chars = charsetStr;
            if (excludeAmbiguous) {
                chars = chars.split('').filter(c => !AMBIGUOUS.has(c)).join('');
            }
            if (!chars) return;
            pool += chars;
            for (let i = 0; i < minRequired; i++) {
                required.push(chars[this.secureRandom(chars.length)]);
            }
        };
        
        if (useLowercase) addCharset('lowercase', this.CHARSETS.lowercase);
        if (useUppercase) addCharset('uppercase', this.CHARSETS.uppercase);
        if (useDigits)    addCharset('digits', this.CHARSETS.digits);
        if (useSpecial)   addCharset('special', this.CHARSETS.special);
        
        if (!pool) pool = this.CHARSETS.lowercase;
        
        const remaining = Math.max(0, length - required.length);
        const extra = Array.from({ length: remaining }, 
            () => pool[this.secureRandom(pool.length)]);
        
        const all = this.secureShuffle([...required, ...extra]);
        return all.join('');
    }
    
    /**
     * Client-side strength analysis (mirrors Python's EntropyAnalyzer)
     */
    static analyzeStrength(password) {
        if (!password) return null;
        
        const freq = {};
        for (const ch of password) freq[ch] = (freq[ch] || 0) + 1;
        const len = password.length;
        let shannon = 0;
        for (const count of Object.values(freq)) {
            const p = count / len;
            if (p > 0) shannon -= p * Math.log2(p);
        }
        
        let charsetSize = 0;
        if (/[a-z]/.test(password)) charsetSize += 26;
        if (/[A-Z]/.test(password)) charsetSize += 26;
        if (/[0-9]/.test(password)) charsetSize += 10;
        if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
        
        const charsetEntropy = charsetSize > 0 
            ? password.length * Math.log2(charsetSize) 
            : 0;
        
        const effectiveEntropy = charsetEntropy * 0.8;  // Apply penalty
        const gpuGuessesPerSec = 10_000_000_000;
        const combinations = Math.pow(2, effectiveEntropy);
        const secondsToCrack = combinations / gpuGuessesPerSec;
        
        const formatTime = (s) => {
            if (s < 60) return `${s.toFixed(1)}s`;
            if (s < 3600) return `${(s/60).toFixed(1)}m`;
            if (s < 86400) return `${(s/3600).toFixed(1)}h`;
            return `${(s/86400).toFixed(1)}d`;
        };
        
        return {
            shannonEntropy: Math.round(shannon * 100) / 100,
            charsetEntropy: Math.round(charsetEntropy * 100) / 100,
            effectiveEntropy: Math.round(effectiveEntropy * 100) / 100,
            length: password.length,
            crackTime: formatTime(secondsToCrack),
            generatedBy: 'client-side-webcrypto',
        };
    }
}

// Service Worker: Install & Cache
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(STATIC_CACHE).then(cache => 
            cache.addAll(PRECACHE_URLS).catch(() => {
                console.warn('Some resources could not be cached');
            })
        )
    );
    self.skipWaiting();
});

// Service Worker: Activate & Cleanup Old Caches
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys => 
            Promise.all(
                keys.filter(k => !k.includes(CACHE_VERSION))
                    .map(k => caches.delete(k))
            )
        )
    );
    self.clients.claim();
});

// Service Worker: Network-first with offline fallback
self.addEventListener('fetch', event => {
    const { request } = event;
    const url = new URL(request.url);
    
    // API calls: Network first, no cache (sensitive data)
    if (url.pathname.startsWith('/api/')) {
        event.respondWith(
            fetch(request).catch(() => {
                return new Response(
                    JSON.stringify({
                        status: 'offline',
                        message: 'Server unavailable. Use client-side generation.',
                        offline_mode: true,
                    }),
                    { headers: { 'Content-Type': 'application/json' } }
                );
            })
        );
        return;
    }
    
    // Static assets: Cache first, network fallback
    event.respondWith(
        caches.match(request)
            .then(cached => cached || fetch(request))
            .catch(() => caches.match('/'))
    );
});
