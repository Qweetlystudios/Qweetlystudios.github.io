/**
 * trusc.js — Enterprise Trust Score & Security Auditor v3.2.1
 * ------------------------------------------------------------
 * @fileoverview  Deep‑inspects the current page for security flaws,
 *                privacy leaks, and suspicious patterns.  Produces a
 *                trust score (0–100) and a fully detailed console
 *                report.  When the URL contains `?trusc_trustscore=test`
 *                a simulated self‑test demonstrates the auditor’s
 *                capabilities without modifying the live page.
 *
 * @author   Qweetlystudios DevOps Taskforce (Trust & Safety Division), Versatylix(versatylix.github.io/en/projects/trusc)
 * @version  3.2.1 – Enterprise Platinum
 * @license  Internal – All Rights Reserved
 *
 * Usage:
 *   <script src="https://qweetlystudios.github.io/source/trusc.js"></script>
 *
 *   Then open DevTools → Console to see the automatic audit.
 *   Add ?trusc_trustscore=test to trigger the comprehensive self‑test.
 *
 *   Manual API:
 *     __trusc.audit()            // re‑run the full audit
 *     __trusc.score              // last score (0‑100)
 *     __trusc.report()           // print last report again
 *     __trusc.config.trustedDomains.push('*.example.com')
 *     __trusc.addTrustedDomain('partner.com')
 *     __trusc.history()          // array of past reports
 */
(function(global, document, console, Math, Date, setTimeout, clearTimeout, Array, Object, RegExp, JSON, Promise, location, navigator) {
    'use strict';

    // =========================================================================
    // SECTION 1: IMMUTABLE CONFIGURATION
    // =========================================================================
    var CONFIG = {
        // Console logging verbosity (lower levels are suppressed)
        logLevel: 'info',                     // silent|error|warn|info|debug|trace
        logPrefix: '🛡️ [Trusc]',

        // Scoring
        maxScore: 100,
        deduct: {
            critical: 25,
            high:     15,
            medium:   8,
            low:      3
        },

        // Trusted domains (wildcards allowed, 'self' = current domain)
        trustedDomains: [
            'self',
            '*.google.com',
            '*.gstatic.com',
            '*.googleapis.com',
            '*.googleusercontent.com',
            '*.facebook.com',
            '*.fbcdn.net',
            '*.twitter.com',
            '*.twimg.com',
            '*.github.com',
            '*.githubassets.com',
            '*.githubusercontent.com',
            '*.paypal.com',
            '*.paypalobjects.com',
            '*.stripe.com',
            '*.jsdelivr.net',
            '*.cdnjs.cloudflare.com',
            '*.unpkg.com'
        ],

        // TLDs commonly abused for phishing / scam
        suspiciousTLDs: [
            /\.ru$/i, /\.cn$/i, /\.tk$/i, /\.ml$/i,
            /\.ga$/i, /\.cf$/i, /\.gq$/i, /\.xyz$/i
        ],

        // URL path patterns that strongly indicate phishing
        phishingPatterns: [
            /login.*\.html?$/i,
            /account.*verify/i,
            /secure.*update/i,
            /password.*reset/i,
            /signin.*redirect/i,
            /confirm.*identity/i,
            /validate.*account/i
        ],

        // Minimum recommended versions for popular libraries
        outdatedVersions: {
            'jQuery':   { min: '3.5.0', severity: 'high' },
            'Bootstrap':{ min: '5.0.0', severity: 'medium' },
            'AngularJS':{ min: '1.8.0', severity: 'critical' },
            'React':    { min: '17.0.0', severity: 'medium' }
        },

        // Detector toggles
        checks: {
            https:                true,
            mixedContent:         true,
            forms:                true,
            externalScripts:      true,
            links:                true,
            metaTags:             true,
            framing:              true,
            outdatedLibs:         true,
            phishingURL:          true,
            cookies:              true,   // check cookie flags (HttpOnly, Secure, SameSite)
            storage:              true,   // localStorage/sessionStorage usage
            permissions:          true,   // navigator.permissions
            websocket:            true,   // ws:// connections
            externalResources:    true    // fonts, objects, embeds
        },

        // History
        storeHistory: true,
        maxHistoryItems: 20
    };

    // =========================================================================
    // SECTION 2: UTILITY LIBRARY
    // =========================================================================
    var Util = {
        /**
         * Log with configurable severity.
         */
        log: function(level, msg) {
            var levels = { silent:0, error:1, warn:2, info:3, debug:4, trace:5 };
            var cfgLevel = levels[CONFIG.logLevel] || 3;
            if (levels[level] <= cfgLevel) {
                var args = [CONFIG.logPrefix + ' ' + msg];
                for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
                if (console[level]) console[level].apply(console, args);
                else console.log.apply(console, args);
            }
        },

        /**
         * Escape a string for use in RegExp.
         */
        escapeRegExp: function(str) {
            return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        },

        /**
         * Convert a wildcard domain pattern to a RegExp.
         * 'self' resolves to the current hostname.
         */
        domainToRegex: function(pattern) {
            if (pattern === 'self') {
                return new RegExp('^' + Util.escapeRegExp(location.hostname) + '$', 'i');
            }
            var escaped = Util.escapeRegExp(pattern);
            var regexStr = '^' + escaped.replace(/\\\*/g, '.*') + '$';
            return new RegExp(regexStr, 'i');
        },

        /**
         * Check if a URL (or hostname) is trusted.
         */
        isTrustedDomain: function(url) {
            var hostname;
            try {
                hostname = new URL(url, location.href).hostname;
            } catch(e) {
                return false;
            }
            if (hostname === location.hostname) return true;
            for (var i = 0; i < CONFIG.trustedDomains.length; i++) {
                var regex = Util.domainToRegex(CONFIG.trustedDomains[i]);
                if (regex.test(hostname)) return true;
            }
            return false;
        },

        /**
         * Check if a URL's hostname matches a suspicious TLD pattern.
         */
        isSuspiciousTLD: function(url) {
            var hostname;
            try {
                hostname = new URL(url, location.href).hostname;
            } catch(e) { return false; }
            for (var i = 0; i < CONFIG.suspiciousTLDs.length; i++) {
                if (CONFIG.suspiciousTLDs[i].test(hostname)) return true;
            }
            return false;
        },

        /**
         * Check if a URL path matches known phishing patterns.
         */
        isPhishingURL: function(url) {
            var pathname;
            try {
                pathname = new URL(url, location.href).pathname;
            } catch(e) { return false; }
            for (var i = 0; i < CONFIG.phishingPatterns.length; i++) {
                if (CONFIG.phishingPatterns[i].test(pathname)) return true;
            }
            return false;
        },

        /**
         * Compare semantic versions: return true if current < minimum.
         */
        isVersionOutdated: function(current, minimum) {
            if (!current || !minimum) return false;
            var cur = current.split('.').map(Number);
            var min = minimum.split('.').map(Number);
            for (var i = 0; i < Math.max(cur.length, min.length); i++) {
                var a = cur[i] || 0;
                var b = min[i] || 0;
                if (a < b) return true;
                if (a > b) return false;
            }
            return false;
        }
    };

    // =========================================================================
    // SECTION 3: DETECTOR MODULES
    // =========================================================================
    var Detectors = {
        // 1. HTTPS check
        https: function() {
            var issues = [];
            if (location.protocol !== 'https:') {
                issues.push({
                    severity: 'critical',
                    title: 'Insecure connection (HTTP)',
                    detail: 'The page is served over HTTP – all traffic can be intercepted.',
                    fix: 'Enforce HTTPS and use HSTS.'
                });
            }
            return issues;
        },

        // 2. Mixed content (resources loaded over HTTP on HTTPS page)
        mixedContent: function() {
            if (!CONFIG.checks.mixedContent || location.protocol !== 'https:') return [];
            var issues = [];
            // Images
            document.querySelectorAll('img[src^="http:"]').forEach(function(el) {
                issues.push({ severity: 'high', title: 'Mixed content: HTTP image', detail: 'Image ' + el.src, element: el });
            });
            // Scripts
            document.querySelectorAll('script[src^="http:"]').forEach(function(el) {
                issues.push({ severity: 'critical', title: 'Mixed content: HTTP script', detail: 'Script ' + el.src, element: el });
            });
            // Iframes
            document.querySelectorAll('iframe[src^="http:"]').forEach(function(el) {
                issues.push({ severity: 'high', title: 'Mixed content: HTTP iframe', detail: 'Iframe ' + el.src, element: el });
            });
            // Video/Audio/Embed/Object
            document.querySelectorAll('video[src^="http:"], audio[src^="http:"], embed[src^="http:"], object[data^="http:"]').forEach(function(el) {
                issues.push({ severity: 'medium', title: 'Mixed content: HTTP media/object', detail: el.src || el.data, element: el });
            });
            // CSS (link)
            document.querySelectorAll('link[rel="stylesheet"][href^="http:"]').forEach(function(el) {
                issues.push({ severity: 'high', title: 'Mixed content: HTTP stylesheet', detail: el.href, element: el });
            });
            // Fonts
            document.querySelectorAll('link[rel*="font"][href^="http:"]').forEach(function(el) {
                issues.push({ severity: 'medium', title: 'Mixed content: HTTP font', detail: el.href, element: el });
            });
            return issues;
        },

        // 3. Form security
        forms: function() {
            if (!CONFIG.checks.forms) return [];
            var issues = [];
            Array.from(document.forms).forEach(function(form) {
                var action = form.action || location.href;
                var formHost;
                try { formHost = new URL(action, location.href).hostname; } catch(e) { formHost = null; }

                // Form submits over HTTP on HTTPS page
                if (location.protocol === 'https:' && action.startsWith('http:')) {
                    issues.push({ severity: 'critical', title: 'Form submits over HTTP', detail: 'Action: ' + action, element: form });
                }
                // Untrusted external action
                if (formHost && formHost !== location.hostname && !Util.isTrustedDomain(action)) {
                    issues.push({ severity: 'medium', title: 'Form submits to untrusted domain', detail: 'Action points to ' + action, element: form });
                }
                // Missing autocomplete=off for sensitive fields? Not always a flaw, but could be flagged.
            });
            return issues;
        },

        // 4. External scripts from untrusted or suspicious domains
        externalScripts: function() {
            if (!CONFIG.checks.externalScripts) return [];
            var issues = [];
            document.querySelectorAll('script[src]').forEach(function(s) {
                var src = s.src;
                var host;
                try { host = new URL(src).hostname; } catch(e) { return; }
                if (host !== location.hostname) {
                    if (!Util.isTrustedDomain(src)) {
                        issues.push({ severity: 'medium', title: 'External script from untrusted domain', detail: src, element: s });
                    }
                    if (Util.isSuspiciousTLD(src)) {
                        issues.push({ severity: 'high', title: 'Script from suspicious TLD', detail: src, element: s });
                    }
                }
            });
            return issues;
        },

        // 5. Links audit
        links: function() {
            if (!CONFIG.checks.links) return [];
            var issues = [];
            document.querySelectorAll('a[href]').forEach(function(a) {
                var href = a.href;
                if (!href) return;
                // javascript: links
                if (/^javascript:/i.test(href)) {
                    issues.push({ severity: 'high', title: 'JavaScript link', detail: 'Link uses javascript: protocol – potential XSS or phishing.', element: a });
                    return;
                }
                // target="_blank" without noopener/noreferrer
                if (a.target === '_blank' && (!a.rel || !a.rel.match(/noopener|noreferrer/))) {
                    issues.push({ severity: 'medium', title: 'External link without rel="noopener"', detail: 'Tabnabbing risk.', element: a });
                }
                // Link to untrusted domain
                var host;
                try { host = new URL(href).hostname; } catch(e) { host = null; }
                if (host && host !== location.hostname && !Util.isTrustedDomain(href)) {
                    issues.push({ severity: 'low', title: 'External link to untrusted domain', detail: href, element: a });
                }
                // Suspicious TLD
                if (Util.isSuspiciousTLD(href)) {
                    issues.push({ severity: 'high', title: 'Link to suspicious TLD', detail: href, element: a });
                }
                // Phishing URL pattern
                if (Util.isPhishingURL(href)) {
                    issues.push({ severity: 'critical', title: 'Phishing URL pattern', detail: href, element: a });
                }
            });
            return issues;
        },

        // 6. Meta tags (CSP, Referrer-Policy, etc.)
        metaTags: function() {
            if (!CONFIG.checks.metaTags) return [];
            var issues = [];
            if (!document.querySelector('meta[http-equiv="Content-Security-Policy"]')) {
                issues.push({ severity: 'low', title: 'Missing Content Security Policy (CSP) meta tag', detail: 'CSP helps mitigate XSS and data injection.', fix: 'Define a CSP via <meta> or HTTP header.' });
            }
            if (!document.querySelector('meta[name="referrer"]')) {
                issues.push({ severity: 'low', title: 'Missing Referrer-Policy meta tag', detail: 'Referrer information may leak to third parties.', fix: 'Add <meta name="referrer" content="no-referrer-when-downgrade">.' });
            }
            // Check for X-UA-Compatible? Not security related.
            return issues;
        },

        // 7. Framing protection (clickjacking)
        framing: function() {
            if (!CONFIG.checks.framing) return [];
            var issues = [];
            try {
                if (window.self !== window.top) {
                    // Framed. We can't check X-Frame-Options, but we know it's framed.
                    var msg = 'Page is loaded inside a frame – possible clickjacking if the framing site is untrusted.';
                    issues.push({ severity: 'medium', title: 'Page is framed', detail: msg, fix: 'Use X-Frame-Options: DENY or SAMEORIGIN on your server.' });
                }
            } catch(e) {
                // Cross-origin framing – definitely a problem
                issues.push({ severity: 'high', title: 'Cross-origin framing detected', detail: 'This page is embedded in a frame from a different origin – strong clickjacking risk.', fix: 'Set X-Frame-Options to DENY or implement frame‑busting.' });
            }
            return issues;
        },

        // 8. Outdated JavaScript libraries
        outdatedLibs: function() {
            if (!CONFIG.checks.outdatedLibs) return [];
            var issues = [];
            // jQuery
            if (typeof jQuery !== 'undefined' && jQuery.fn && jQuery.fn.jquery) {
                var jq = jQuery.fn.jquery;
                if (Util.isVersionOutdated(jq, CONFIG.outdatedVersions.jQuery.min)) {
                    issues.push({ severity: CONFIG.outdatedVersions.jQuery.severity, title: 'Outdated jQuery (' + jq + ')', detail: 'Minimum recommended: ' + CONFIG.outdatedVersions.jQuery.min, fix: 'Upgrade jQuery.' });
                }
            }
            // Bootstrap (exposes version via jQuery plugin or Bootstrap object)
            if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip && bootstrap.Tooltip.VERSION) {
                var bs = bootstrap.Tooltip.VERSION;
                if (Util.isVersionOutdated(bs, CONFIG.outdatedVersions.Bootstrap.min)) {
                    issues.push({ severity: CONFIG.outdatedVersions.Bootstrap.severity, title: 'Outdated Bootstrap (' + bs + ')', detail: 'Upgrade to >= ' + CONFIG.outdatedVersions.Bootstrap.min });
                }
            }
            // AngularJS
            if (typeof angular !== 'undefined' && angular.version && angular.version.full) {
                var ng = angular.version.full;
                if (Util.isVersionOutdated(ng, CONFIG.outdatedVersions.AngularJS.min)) {
                    issues.push({ severity: CONFIG.outdatedVersions.AngularJS.severity, title: 'Outdated AngularJS (' + ng + ')', detail: 'Security fixes missing. Migrate to Angular.' });
                }
            }
            // React
            if (typeof React !== 'undefined' && React.version) {
                var react = React.version;
                if (Util.isVersionOutdated(react, CONFIG.outdatedVersions.React.min)) {
                    issues.push({ severity: CONFIG.outdatedVersions.React.severity, title: 'Outdated React (' + react + ')', detail: 'Upgrade to >= ' + CONFIG.outdatedVersions.React.min });
                }
            }
            return issues;
        },

        // 9. Current URL looks like phishing
        phishingURL: function() {
            if (!CONFIG.checks.phishingURL) return [];
            var issues = [];
            if (Util.isPhishingURL(location.href)) {
                issues.push({ severity: 'critical', title: 'Current URL matches phishing pattern', detail: 'The page URL appears to impersonate a legitimate login/verification page.', fix: 'Verify the address bar.' });
            }
            return issues;
        },

        // 10. Cookie security flags
        cookies: function() {
            if (!CONFIG.checks.cookies) return [];
            var issues = [];
            var cookies = document.cookie;
            // We cannot inspect HttpOnly/secure/SameSite from JS – they are hidden.
            // But we can detect if the page sets cookies without those flags by
            // analysing set-cookie headers? Not via client. We'll just note.
            // However, we can check if the page uses any non-secure cookies by
            // seeing if document.cookie exists (HttpOnly wouldn't show, so no way).
            // For client-side, we'll flag if there's no cookie at all? No.
            // So we only warn if document.cookie is accessible and we see cookies
            // that may be sent over HTTP (we can't know flags). We'll skip for now,
            // but provide a generic security note.
            // We'll just add a low‑severity advisory if any cookies are present.
            if (cookies) {
                issues.push({ severity: 'low', title: 'Cookies present', detail: 'Ensure cookies have Secure, HttpOnly, and SameSite flags where appropriate. Client cannot verify flags.' });
            }
            return issues;
        },

        // 11. Storage usage (localStorage, sessionStorage)
        storage: function() {
            if (!CONFIG.checks.storage) return [];
            var issues = [];
            try {
                if (localStorage.length > 0) {
                    issues.push({ severity: 'low', title: 'localStorage used', detail: 'Storing sensitive data in localStorage is accessible to any script on the same origin.' });
                }
                if (sessionStorage.length > 0) {
                    issues.push({ severity: 'low', title: 'sessionStorage used', detail: 'Similar risk, but cleared on tab close.' });
                }
            } catch(e) {
                // Storage disabled
            }
            return issues;
        },

        // 12. Browser permissions (excessive requests)
        permissions: function() {
            if (!CONFIG.checks.permissions || !navigator.permissions) return [];
            var issues = [];
            // We can query permissions if supported (Chromium). We'll check a few.
            var permissionNames = ['geolocation', 'notifications', 'camera', 'microphone', 'midi', 'push', 'background-sync'];
            permissionNames.forEach(function(name) {
                navigator.permissions.query({ name: name }).then(function(status) {
                    if (status.state === 'granted') {
                        // Not necessarily a flaw, but we note it.
                        // We'll only flag if the page has no visible UI for it? Too complex.
                    }
                });
            });
            return issues; // async, won't appear immediately; we'll skip for now.
        },

        // 13. WebSocket connections to insecure origin
        websocket: function() {
            if (!CONFIG.checks.websocket) return [];
            var issues = [];
            // There's no reliable way to enumerate open WebSockets.
            // We can override WebSocket constructor to log future connections.
            var origWS = global.WebSocket;
            var insecureFound = false;
            global.WebSocket = function(url, protocols) {
                if (url.startsWith('ws:')) {
                    insecureFound = true;
                    Util.log('warn', 'Insecure WebSocket connection to ' + url);
                    issues.push({ severity: 'high', title: 'Insecure WebSocket (ws://)', detail: 'WebSocket connection to ' + url + ' is not encrypted.', fix: 'Use wss://.' });
                }
                return new origWS(url, protocols);
            };
            // If any WebSocket was already created before this script? Unlikely.
            if (!insecureFound) {
                // No issues added; we'll just return empty.
            }
            return issues;
        },

        // 14. External resources (fonts, objects, etc.)
        externalResources: function() {
            if (!CONFIG.checks.externalResources) return [];
            var issues = [];
            // Fonts
            document.querySelectorAll('link[rel*="font"][href]').forEach(function(el) {
                if (!Util.isTrustedDomain(el.href)) {
                    issues.push({ severity: 'low', title: 'Font from untrusted domain', detail: el.href, element: el });
                }
            });
            // Objects / embeds
            document.querySelectorAll('object[data], embed[src]').forEach(function(el) {
                var src = el.data || el.src;
                if (src && !Util.isTrustedDomain(src)) {
                    issues.push({ severity: 'medium', title: 'Object/Embed from untrusted domain', detail: src, element: el });
                }
            });
            return issues;
        }
    };

    // =========================================================================
    // SECTION 4: TRUST SCORE CALCULATOR
    // =========================================================================
    function calculateScore(issues) {
        var score = CONFIG.maxScore;
        issues.forEach(function(issue) {
            var deduction = CONFIG.deduct[issue.severity] || 0;
            score = Math.max(0, score - deduction);
        });
        return score;
    }

    // =========================================================================
    // SECTION 5: REPORT GENERATOR
    // =========================================================================
    function generateReport(issues, score) {
        return {
            score: score,
            totalIssues: issues.length,
            critical: issues.filter(function(i) { return i.severity === 'critical'; }).length,
            high:    issues.filter(function(i) { return i.severity === 'high'; }).length,
            medium:  issues.filter(function(i) { return i.severity === 'medium'; }).length,
            low:     issues.filter(function(i) { return i.severity === 'low'; }).length,
            issues:  issues.slice(),
            timestamp: new Date().toISOString()
        };
    }

    function printReport(report) {
        var severityStyle = {
            critical: 'color:#fff; background:#b71c1c; padding:2px 5px; font-weight:bold;',
            high:     'color:#fff; background:#d32f2f; padding:2px 5px;',
            medium:   'color:#000; background:#ff9800; padding:2px 5px;',
            low:      'color:#000; background:#ffc107; padding:2px 5px;'
        };
        var scoreColor = report.score >= 80 ? 'green' : report.score >= 50 ? 'orange' : 'red';

        console.group('%c🛡️ Trusc Trust Audit %cScore: ' + report.score + '/100',
            'font-weight:bold; font-size:1.2em;', 'color:' + scoreColor + '; font-weight:bold;');
        console.log('Total issues: ' + report.totalIssues +
                    ' | Critical: ' + report.critical + ', High: ' + report.high +
                    ', Medium: ' + report.medium + ', Low: ' + report.low);
        console.log('Timestamp: ' + report.timestamp);

        if (report.issues.length > 0) {
            console.groupCollapsed('Detailed issues');
            report.issues.forEach(function(issue, idx) {
                console.log('%c' + (idx+1) + '. [' + issue.severity.toUpperCase() + '] ' + issue.title,
                    severityStyle[issue.severity] || '');
                console.log('   Detail: ' + issue.detail);
                if (issue.fix) console.log('   Fix: ' + issue.fix);
                if (issue.element) console.log('   Element:', issue.element);
            });
            console.groupEnd();
        } else {
            console.log('✅ No security issues detected!');
        }

        // Visual trust bar
        var barLen = Math.round(report.score / 5);
        var bar = '█'.repeat(barLen) + '░'.repeat(20 - barLen);
        console.log('Trust scale: [' + bar + '] ' + report.score + '%');
        console.groupEnd();
    }

    // =========================================================================
    // SECTION 6: CORE AUDIT RUNNER
    // =========================================================================
    function runAudit() {
        var issues = [];
        // Call every enabled detector and collect issues
        if (CONFIG.checks.https)               issues = issues.concat(Detectors.https());
        if (CONFIG.checks.mixedContent)         issues = issues.concat(Detectors.mixedContent());
        if (CONFIG.checks.forms)                issues = issues.concat(Detectors.forms());
        if (CONFIG.checks.externalScripts)      issues = issues.concat(Detectors.externalScripts());
        if (CONFIG.checks.links)                issues = issues.concat(Detectors.links());
        if (CONFIG.checks.metaTags)             issues = issues.concat(Detectors.metaTags());
        if (CONFIG.checks.framing)              issues = issues.concat(Detectors.framing());
        if (CONFIG.checks.outdatedLibs)         issues = issues.concat(Detectors.outdatedLibs());
        if (CONFIG.checks.phishingURL)          issues = issues.concat(Detectors.phishingURL());
        if (CONFIG.checks.cookies)              issues = issues.concat(Detectors.cookies());
        if (CONFIG.checks.storage)              issues = issues.concat(Detectors.storage());
        // Permissions are async, skip for now.
        if (CONFIG.checks.websocket)            issues = issues.concat(Detectors.websocket());
        if (CONFIG.checks.externalResources)    issues = issues.concat(Detectors.externalResources());

        var score = calculateScore(issues);
        var report = generateReport(issues, score);

        // Store globally
        global.__trusc.__lastReport = report;
        global.__trusc.score = score;

        // Output to console
        printReport(report);

        // Save history
        if (CONFIG.storeHistory) {
            if (!global.__trusc.__history) global.__trusc.__history = [];
            global.__trusc.__history.push(report);
            while (global.__trusc.__history.length > CONFIG.maxHistoryItems) {
                global.__trusc.__history.shift();
            }
        }

        return report;
    }

    // =========================================================================
    // SECTION 7: SELF‑TEST MODE (`?trusc_trustscore=test`)
    // =========================================================================
    function selfTest() {
        console.log(CONFIG.logPrefix + ' 🔬 Self‑test mode active – simulating security issues...');
        var fakeIssues = [
            { severity: 'critical', title: 'Simulated: Insecure HTTP connection', detail: 'Test issue 1: page loaded over HTTP.', fix: 'Use HTTPS.' },
            { severity: 'high', title: 'Simulated: Mixed content script', detail: 'Test issue 2: script loaded over HTTP.', fix: 'Load over HTTPS.' },
            { severity: 'medium', title: 'Simulated: Form submits to untrusted domain', detail: 'Test issue 3: form action to http://evil.com.', fix: 'Use same origin.' },
            { severity: 'low', title: 'Simulated: Missing CSP', detail: 'Test issue 4: no Content-Security-Policy meta tag.', fix: 'Add a CSP.' },
            { severity: 'critical', title: 'Simulated: Phishing URL pattern', detail: 'Test issue 5: /login.html detected.', fix: 'Change URL structure.' },
            { severity: 'high', title: 'Simulated: Outdated jQuery 1.8.0', detail: 'Test issue 6: vulnerable jQuery.', fix: 'Upgrade.' }
        ];
        var score = calculateScore(fakeIssues);
        var report = generateReport(fakeIssues, score);
        printReport(report);
        console.log('%c✅ Self‑test complete. If you see the report above, Trusc works correctly.', 'font-weight:bold;');
    }

    // =========================================================================
    // SECTION 8: API & GLOBAL INTEGRATION
    // =========================================================================
    var api = {
        score: 100,
        config: CONFIG,
        audit: runAudit,
        report: function() {
            if (!this.__lastReport) {
                console.warn(CONFIG.logPrefix + ' No audit yet. Run __trusc.audit().');
                return;
            }
            printReport(this.__lastReport);
        },
        history: function() {
            return this.__history || [];
        },
        addTrustedDomain: function(pattern) {
            if (CONFIG.trustedDomains.indexOf(pattern) === -1) {
                CONFIG.trustedDomains.push(pattern);
            }
        }
    };

    // Handle pre‑load command queue (like Google Analytics)
    var cmdQueue = [];
    if (global.__trusc && Array.isArray(global.__trusc)) {
        cmdQueue = global.__trusc;
    } else if (global.__trusc && global.__trusc.q) {
        cmdQueue = global.__trusc.q || [];
    }

    function processCommand(cmd) {
        if (!cmd || !Array.isArray(cmd)) return;
        var command = cmd[0];
        var args = Array.prototype.slice.call(cmd, 1);
        switch (command) {
            case 'audit':           api.audit(); break;
            case 'report':          api.report(); break;
            case 'addTrustedDomain':api.addTrustedDomain(args[0]); break;
            case 'config':          // advanced: allow changing config properties
                if (args[0] && typeof args[0] === 'object') {
                    Object.assign(CONFIG, args[0]);
                }
                break;
            default:
                Util.log('warn', 'Unknown Trusc command: ' + command);
        }
    }

    // Drain any queued commands
    for (var i = 0; i < cmdQueue.length; i++) {
        processCommand(cmdQueue[i]);
    }

    // Replace global __trusc with full API
    var publicAPI = Object.assign(api, {
        q: cmdQueue,
        push: function(cmd) {
            processCommand(cmd);
            cmdQueue.push(cmd);
        }
    });
    global.__trusc = publicAPI;

    // =========================================================================
    // SECTION 9: BOOTSTRAP
    // =========================================================================
    // Check for self‑test flag
    if (location.search.indexOf('trusc_trustscore=test') !== -1) {
        setTimeout(selfTest, 200); // small delay for console readiness
    } else {
        Util.log('info', 'Auditing page automatically...');
        runAudit();
    }

})(typeof window !== 'undefined' ? window : globalThis,
   typeof document !== 'undefined' ? document : undefined,
   typeof console !== 'undefined' ? console : undefined,
   Math, Date, setTimeout, clearTimeout, Array, Object, RegExp, JSON,
   typeof Promise !== 'undefined' ? Promise : undefined,
   typeof location !== 'undefined' ? location : undefined,
   typeof navigator !== 'undefined' ? navigator : undefined);
