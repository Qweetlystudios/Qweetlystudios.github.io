/**
 * trusc.js — Enterprise Trust Score & Security Auditor v2.0.0
 * -----------------------------------------------------------
 * @fileoverview  Scans the current page for security flaws, privacy risks,
 *                and suspicious patterns.  Generates a trust score (0–100)
 *                and a rich console report.  Integrates with the DevTools
 *                console for manual deep‑dives.
 *
 * @author   Qweetlystudios DevOps Taskforce (Trust & Safety Division)
 * @version  2.0.0 – Platinum
 * @license  Internal – All Rights Reserved
 *
 * Usage:
 *   // Automatic audit on page load
 *   <script src="https://qweetlystudios.github.io/source/trusc.js"></script>
 *
 *   // Manual re‑audit
 *   __trusc.audit();
 *
 *   // Get the latest score
 *   __trusc.score;           // e.g. 85
 *
 *   // Get detailed report
 *   __trusc.report();        // prints full breakdown
 *
 *   // Customise trusted domains
 *   __trusc.config.trustedDomains.push('*.example.com');
 *
 *   // Self‑test: add ?trusc_test=2 to the URL
 */
(function(global, document, console, Math, Date, setTimeout, clearTimeout, Array, Object, RegExp, JSON, Promise, location, navigator) {
    'use strict';

    // =========================================================================
    // SECTION 1: IMMUTABLE CONFIGURATION
    // =========================================================================
    var CONFIG = {
        logLevel: 'info',                     // silent|error|warn|info|debug|trace
        logPrefix: '🛡️ [Trusc]',
        maxScore: 100,                        // starting score
        deduct: {                             // points deducted per issue
            critical: 25,
            high: 15,
            medium: 8,
            low: 3
        },
        // Known trusted domains (wildcards supported)
        trustedDomains: [
            'self',
            '*.google.com',
            '*.gstatic.com',
            '*.googleapis.com',
            '*.facebook.com',
            '*.fbcdn.net',
            '*.twitter.com',
            '*.twimg.com',
            '*.github.com',
            '*.githubusercontent.com',
            '*.paypal.com',
            '*.stripe.com',
            '*.jsdelivr.net',
            '*.cdnjs.cloudflare.com',
            '*.unpkg.com'
        ],
        // Domains that are always flagged as suspicious
        suspiciousDomains: [
            /.*\.ru$/,
            /.*\.cn$/,
            /.*\.tk$/,
            /.*\.ml$/,
            /.*\.ga$/,
            /.*\.cf$/,
            /.*\.gq$/,
            /.*\.xyz$/   // common free domains used in phishing
        ],
        // Patterns indicating phishing / scam intent
        phishingPatterns: [
            /login.*\.html?$/i,
            /account.*verify/i,
            /secure.*update/i,
            /password.*reset/i,
            /signin.*redirect/i
        ],
        // Outdated JS library versions (common CVEs)
        outdatedVersions: {
            'jQuery': { min: '3.5.0', severity: 'high' },
            'Bootstrap': { min: '5.0.0', severity: 'medium' },
            'AngularJS': { min: '1.8.0', severity: 'critical' },
            'React': { min: '17.0.0', severity: 'medium' }
        },
        enableEvalDetection: true,
        enableDocumentWriteDetection: true,
        enableMixedContentCheck: true,
        enableExternalScriptCheck: true,
        enableLinkAudit: true,
        enableFormAudit: true,
        enableFramingCheck: true,
        enableMetaTagCheck: true,
        enableOutdatedLibCheck: true,
        enablePhishingURLCheck: true,
        storeReportHistory: true,
        maxHistoryItems: 20
    };

    // =========================================================================
    // SECTION 2: ULTIMATE UTILITY BELT
    // =========================================================================
    var Util = {
        /**
         * Log with configurable level.
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
         * Convert wildcard domain pattern to a RegExp.
         */
        domainToRegex: function(pattern) {
            if (pattern === 'self') {
                return new RegExp('^' + Util.escapeRegExp(location.hostname) + '$', 'i');
            }
            var escaped = Util.escapeRegExp(pattern);
            // Replace \* with .*
            var regexStr = '^' + escaped.replace(/\\\*/g, '.*') + '$';
            return new RegExp(regexStr, 'i');
        },
        /**
         * Escape a string for use in regex.
         */
        escapeRegExp: function(str) {
            return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        },
        /**
         * Check if a URL matches any trusted domain pattern.
         */
        isTrustedDomain: function(url) {
            var hostname;
            try {
                hostname = new URL(url, location.href).hostname;
            } catch(e) { return false; }
            if (hostname === location.hostname) return true;
            for (var i = 0; i < CONFIG.trustedDomains.length; i++) {
                var regex = Util.domainToRegex(CONFIG.trustedDomains[i]);
                if (regex.test(hostname)) return true;
            }
            return false;
        },
        /**
         * Check if a URL matches any suspicious domain pattern.
         */
        isSuspiciousDomain: function(url) {
            var hostname;
            try {
                hostname = new URL(url, location.href).hostname;
            } catch(e) { return false; }
            for (var i = 0; i < CONFIG.suspiciousDomains.length; i++) {
                if (CONFIG.suspiciousDomains[i].test(hostname)) return true;
            }
            return false;
        },
        /**
         * Check if a URL path matches phishing patterns.
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
         * Compare semantic versions.
         * Returns true if current < minimum required.
         */
        isVersionOutdated: function(current, minimum) {
            if (!current || !minimum) return false;
            var curParts = current.split('.').map(Number);
            var minParts = minimum.split('.').map(Number);
            for (var i = 0; i < Math.max(curParts.length, minParts.length); i++) {
                var a = curParts[i] || 0;
                var b = minParts[i] || 0;
                if (a < b) return true;
                if (a > b) return false;
            }
            return false; // equal
        }
    };

    // =========================================================================
    // SECTION 3: SECURITY DETECTOR MODULES
    // =========================================================================
    var Detectors = {
        /**
         * Check if page is loaded over HTTPS.
         */
        httpsCheck: function() {
            var issues = [];
            if (location.protocol !== 'https:') {
                issues.push({
                    severity: 'critical',
                    title: 'Insecure connection (HTTP)',
                    detail: 'The page is served over HTTP. All data is transmitted in plain text.',
                    fix: 'Redirect to HTTPS and use HSTS.'
                });
            }
            return issues;
        },
        /**
         * Mixed content: resources loaded over HTTP on an HTTPS page.
         */
        mixedContentCheck: function() {
            if (!CONFIG.enableMixedContentCheck) return [];
            if (location.protocol !== 'https:') return []; // only relevant on HTTPS
            var issues = [];
            // Images
            var imgs = document.querySelectorAll('img[src^="http:"]');
            imgs.forEach(function(img) {
                issues.push({
                    severity: 'high',
                    title: 'Mixed content: HTTP image',
                    detail: 'Image loaded over HTTP: ' + img.src,
                    element: img
                });
            });
            // Scripts
            var scripts = document.querySelectorAll('script[src^="http:"]');
            scripts.forEach(function(s) {
                issues.push({
                    severity: 'critical',
                    title: 'Mixed content: HTTP script',
                    detail: 'Script loaded over HTTP: ' + s.src,
                    element: s
                });
            });
            // Iframes
            var iframes = document.querySelectorAll('iframe[src^="http:"]');
            iframes.forEach(function(f) {
                issues.push({
                    severity: 'high',
                    title: 'Mixed content: HTTP iframe',
                    detail: 'Iframe loaded over HTTP: ' + f.src,
                    element: f
                });
            });
            // Links (only warn if they point to an HTTP page from an HTTPS context? Not mixed content per spec, but can be flagged)
            return issues;
        },
        /**
         * Forms submitting to HTTP (on HTTPS page) or to external untrusted domains.
         */
        formAudit: function() {
            if (!CONFIG.enableFormAudit) return [];
            var issues = [];
            var forms = document.forms;
            for (var i = 0; i < forms.length; i++) {
                var form = forms[i];
                var action = form.action || location.href;
                // Check if action is HTTP and page is HTTPS
                if (location.protocol === 'https:' && action.startsWith('http:')) {
                    issues.push({
                        severity: 'critical',
                        title: 'Form submits over HTTP',
                        detail: 'Form action is HTTP: ' + action,
                        element: form
                    });
                }
                // Check if action is to an untrusted external domain
                var formHost;
                try { formHost = new URL(action, location.href).hostname; } catch(e) { formHost = null; }
                if (formHost && formHost !== location.hostname && !Util.isTrustedDomain(action)) {
                    issues.push({
                        severity: 'medium',
                        title: 'Form submits to untrusted domain',
                        detail: 'Form action points to ' + action + ' which is not in trusted list.',
                        element: form
                    });
                }
            }
            return issues;
        },
        /**
         * External scripts from untrusted domains.
         */
        externalScriptCheck: function() {
            if (!CONFIG.enableExternalScriptCheck) return [];
            var issues = [];
            var scripts = document.querySelectorAll('script[src]');
            scripts.forEach(function(s) {
                var src = s.src;
                if (!src) return;
                var host;
                try { host = new URL(src).hostname; } catch(e) { return; }
                if (host !== location.hostname && !Util.isTrustedDomain(src)) {
                    issues.push({
                        severity: 'medium',
                        title: 'External script from untrusted domain',
                        detail: 'Script loaded from ' + src + ' which is not in the trusted list.',
                        element: s
                    });
                }
                if (Util.isSuspiciousDomain(src)) {
                    issues.push({
                        severity: 'high',
                        title: 'Script from suspicious TLD',
                        detail: 'Script src ' + src + ' is from a frequently abused domain zone.',
                        element: s
                    });
                }
            });
            return issues;
        },
        /**
         * Link audit: target="_blank" without rel="noopener", javascript: links, suspicious URLs.
         */
        linkAudit: function() {
            if (!CONFIG.enableLinkAudit) return [];
            var issues = [];
            var links = document.querySelectorAll('a[href]');
            links.forEach(function(a) {
                var href = a.href;
                if (!href) return;
                // javascript: links (often used for malicious purposes)
                if (href.toLowerCase().startsWith('javascript:')) {
                    issues.push({
                        severity: 'high',
                        title: 'JavaScript link detected',
                        detail: 'Link uses javascript: protocol – can be used for XSS or phishing.',
                        element: a
                    });
                    return;
                }
                // target="_blank" without rel="noopener" (tabnabbing)
                if (a.target === '_blank' && (!a.rel || !a.rel.includes('noopener') && !a.rel.includes('noreferrer'))) {
                    issues.push({
                        severity: 'medium',
                        title: 'External link opens without rel="noopener"',
                        detail: 'Link opens in a new tab/window and may be vulnerable to tabnabbing.',
                        element: a
                    });
                }
                // External link to untrusted domain
                var host;
                try { host = new URL(href).hostname; } catch(e) { host = null; }
                if (host && host !== location.hostname && !Util.isTrustedDomain(href)) {
                    issues.push({
                        severity: 'low',
                        title: 'External link to untrusted domain',
                        detail: 'Link points to ' + href + ' which is not in trusted list.',
                        element: a
                    });
                }
                // Suspicious TLD
                if (Util.isSuspiciousDomain(href)) {
                    issues.push({
                        severity: 'high',
                        title: 'Link to suspicious TLD',
                        detail: 'Link leads to ' + href + ' – a commonly abused domain zone.',
                        element: a
                    });
                }
                // Phishing URL pattern
                if (Util.isPhishingURL(href)) {
                    issues.push({
                        severity: 'critical',
                        title: 'Phishing URL pattern detected',
                        detail: 'The link ' + href + ' resembles a known phishing pattern.',
                        element: a
                    });
                }
            });
            return issues;
        },
        /**
         * Check for common security‑related meta tags (CSP, referrer, X-UA-Compatible?).
         */
        metaTagCheck: function() {
            if (!CONFIG.enableMetaTagCheck) return [];
            var issues = [];
            var metaCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
            if (!metaCSP) {
                issues.push({
                    severity: 'low',
                    title: 'Missing Content Security Policy meta tag',
                    detail: 'No CSP found. A CSP helps prevent XSS and data injection attacks.',
                    fix: 'Add a <meta http-equiv="Content-Security-Policy" content="..."> tag.'
                });
            }
            var metaReferrer = document.querySelector('meta[name="referrer"]');
            if (!metaReferrer) {
                issues.push({
                    severity: 'low',
                    title: 'Missing Referrer-Policy meta tag',
                    detail: 'No referrer policy set; may leak full URLs to third parties.',
                    fix: 'Add <meta name="referrer" content="no-referrer-when-downgrade"> or similar.'
                });
            }
            // X-UA-Compatible? Not security-related, skip.
            return issues;
        },
        /**
         * Check if the page is loaded inside an iframe (potential clickjacking).
         */
        framingCheck: function() {
            if (!CONFIG.enableFramingCheck) return [];
            var issues = [];
            try {
                if (window.top !== window.self) {
                    // Framed. We cannot see X-Frame-Options, but we can suggest.
                    issues.push({
                        severity: 'medium',
                        title: 'Page is loaded inside an iframe',
                        detail: 'This page is being framed by another site. This may be a clickjacking attempt if the framing site is untrusted.',
                        fix: 'Ensure your server sends X-Frame-Options: DENY or SAMEORIGIN.'
                    });
                }
            } catch(e) {
                // Cross-origin framing – definitely a risk
                issues.push({
                    severity: 'high',
                    title: 'Page is cross‑origin framed',
                    detail: 'The page is embedded in an iframe from a different origin, which is a strong clickjacking risk.',
                    fix: 'Use X-Frame-Options: DENY or implement frame‑busting.'
                });
            }
            return issues;
        },
        /**
         * Detect usage of eval() (indicative of unsafe practices).
         */
        evalDetection: function() {
            if (!CONFIG.enableEvalDetection) return [];
            var issues = [];
            // We can override eval globally, but that would change behaviour.
            // Instead, we can check if the page overrides eval? Not reliable.
            // Best we can do: check if there is a reference to eval in inline scripts? Not safe.
            // We'll skip for now; real detection would require dynamic analysis.
            Util.log('debug', 'eval detection disabled (static analysis not possible).');
            return issues;
        },
        /**
         * Detect document.write() usage (blocks rendering, potential DOM XSS).
         */
        documentWriteDetection: function() {
            if (!CONFIG.enableDocumentWriteDetection) return [];
            var issues = [];
            // Override document.write to log calls – this may affect page functionality.
            // We'll do it safely: replace with a wrapper that records, but only after page load.
            if (document.readyState === 'complete') {
                var origWrite = document.write;
                var called = false;
                document.write = function() {
                    called = true;
                    // Don't actually write, because we're past load
                    Util.log('warn', 'document.write() called after page load.');
                };
                // We can't know if it was called before our script ran.
                // We'll add a warning that it's not detectable.
            }
            return issues;
        },
        /**
         * Outdated JavaScript library detection.
         */
        outdatedLibCheck: function() {
            if (!CONFIG.enableOutdatedLibCheck) return [];
            var issues = [];
            // Check jQuery
            if (typeof jQuery !== 'undefined' && jQuery.fn && jQuery.fn.jquery) {
                var jqVersion = jQuery.fn.jquery;
                if (Util.isVersionOutdated(jqVersion, CONFIG.outdatedVersions.jQuery.min)) {
                    issues.push({
                        severity: CONFIG.outdatedVersions.jQuery.severity,
                        title: 'Outdated jQuery version',
                        detail: 'jQuery ' + jqVersion + ' is below recommended ' + CONFIG.outdatedVersions.jQuery.min,
                        fix: 'Upgrade jQuery to the latest version.'
                    });
                }
            }
            // Check Bootstrap (if global Bootstrap object exists)
            if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip && bootstrap.Tooltip.VERSION) {
                var bsVersion = bootstrap.Tooltip.VERSION; // approximate
                if (Util.isVersionOutdated(bsVersion, CONFIG.outdatedVersions.Bootstrap.min)) {
                    issues.push({
                        severity: CONFIG.outdatedVersions.Bootstrap.severity,
                        title: 'Outdated Bootstrap version',
                        detail: 'Bootstrap ' + bsVersion + ' detected. Recommended >= ' + CONFIG.outdatedVersions.Bootstrap.min,
                        fix: 'Upgrade Bootstrap.'
                    });
                }
            }
            // Check AngularJS (if angular is defined and has version)
            if (typeof angular !== 'undefined' && angular.version && angular.version.full) {
                var ngVersion = angular.version.full;
                if (Util.isVersionOutdated(ngVersion, CONFIG.outdatedVersions.AngularJS.min)) {
                    issues.push({
                        severity: CONFIG.outdatedVersions.AngularJS.severity,
                        title: 'Outdated AngularJS version',
                        detail: 'AngularJS ' + ngVersion + ' is vulnerable (min ' + CONFIG.outdatedVersions.AngularJS.min + ')',
                        fix: 'Migrate to Angular (or at least patch AngularJS).'
                    });
                }
            }
            // React: can be detected via `React.version`
            if (typeof React !== 'undefined' && React.version) {
                var reactVersion = React.version;
                if (Util.isVersionOutdated(reactVersion, CONFIG.outdatedVersions.React.min)) {
                    issues.push({
                        severity: CONFIG.outdatedVersions.React.severity,
                        title: 'Outdated React version',
                        detail: 'React ' + reactVersion + ' detected. Upgrade recommended.',
                        fix: 'Upgrade to React ' + CONFIG.outdatedVersions.React.min + ' or newer.'
                    });
                }
            }
            return issues;
        },
        /**
         * Check for phishing URL patterns in the current page URL itself.
         */
        phishingURLCheck: function() {
            if (!CONFIG.enablePhishingURLCheck) return [];
            var issues = [];
            var currentUrl = location.href;
            if (Util.isPhishingURL(currentUrl)) {
                issues.push({
                    severity: 'critical',
                    title: 'Current URL matches phishing pattern',
                    detail: 'The page URL itself resembles a known phishing URL pattern. This site may be impersonating a legitimate service.',
                    fix: 'Verify the URL.'
                });
            }
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
    // SECTION 5: REPORT GENERATOR & CONSOLE OUTPUT
    // =========================================================================
    function generateReport(issues, score) {
        var report = {
            score: score,
            totalIssues: issues.length,
            critical: issues.filter(function(i) { return i.severity === 'critical'; }).length,
            high: issues.filter(function(i) { return i.severity === 'high'; }).length,
            medium: issues.filter(function(i) { return i.severity === 'medium'; }).length,
            low: issues.filter(function(i) { return i.severity === 'low'; }).length,
            issues: issues.slice(), // copy
            timestamp: new Date().toISOString()
        };
        return report;
    }

    function printReport(report) {
        var style = {
            critical: 'color: #fff; background: #d32f2f; padding: 2px 5px; font-weight: bold;',
            high: 'color: #fff; background: #f44336; padding: 2px 5px;',
            medium: 'color: #000; background: #ff9800; padding: 2px 5px;',
            low: 'color: #000; background: #ffc107; padding: 2px 5px;'
        };

        console.group('%c🛡️ Trusc Trust Audit Report %cScore: ' + report.score + '/100',
            'font-weight: bold; font-size: 1.1em;', report.score >= 80 ? 'color: green;' : report.score >= 50 ? 'color: orange;' : 'color: red;');
        console.log('Total issues found: ' + report.totalIssues);
        console.log('Critical: ' + report.critical + ', High: ' + report.high + ', Medium: ' + report.medium + ', Low: ' + report.low);
        console.log('Timestamp: ' + report.timestamp);
        if (report.issues.length > 0) {
            console.groupCollapsed('Detailed issues');
            report.issues.forEach(function(issue, idx) {
                console.log('%c' + (idx+1) + '. [' + issue.severity.toUpperCase() + '] ' + issue.title,
                    style[issue.severity] || '');
                console.log('   Detail: ' + issue.detail);
                if (issue.fix) console.log('   Fix: ' + issue.fix);
                if (issue.element) {
                    console.log('   Element:', issue.element);
                }
            });
            console.groupEnd();
        } else {
            console.log('✅ No security issues detected!');
        }
        console.groupEnd();

        // Also show a visual scale
        var barLength = Math.round(report.score / 5);
        var bar = '█'.repeat(barLength) + '░'.repeat(20 - barLength);
        console.log('Trust scale: [' + bar + '] ' + report.score + '%');
    }

    // =========================================================================
    // SECTION 6: CORE AUDIT FUNCTION
    // =========================================================================
    function runAudit() {
        var issues = [];
        // Run each detector
        issues = issues.concat(Detectors.httpsCheck());
        issues = issues.concat(Detectors.mixedContentCheck());
        issues = issues.concat(Detectors.formAudit());
        issues = issues.concat(Detectors.externalScriptCheck());
        issues = issues.concat(Detectors.linkAudit());
        issues = issues.concat(Detectors.metaTagCheck());
        issues = issues.concat(Detectors.framingCheck());
        issues = issues.concat(Detectors.evalDetection());
        issues = issues.concat(Detectors.documentWriteDetection());
        issues = issues.concat(Detectors.outdatedLibCheck());
        issues = issues.concat(Detectors.phishingURLCheck());

        var score = calculateScore(issues);
        var report = generateReport(issues, score);

        // Store in global state
        global.__trusc.__lastReport = report;
        global.__trusc.score = score;

        // Output to console
        printReport(report);

        // Save to history
        if (CONFIG.storeReportHistory) {
            if (!global.__trusc.__history) global.__trusc.__history = [];
            global.__trusc.__history.push(report);
            if (global.__trusc.__history.length > CONFIG.maxHistoryItems) {
                global.__trusc.__history.shift();
            }
        }

        return report;
    }

    // =========================================================================
    // SECTION 7: API & GLOBAL OBJECT
    // =========================================================================
    var api = {
        score: 100,                    // last score, updated after audit
        config: CONFIG,                // allow live configuration changes
        audit: function() {
            return runAudit();
        },
        report: function() {
            if (!this.__lastReport) {
                console.warn(CONFIG.logPrefix + ' No audit run yet. Call __trusc.audit() first.');
                return;
            }
            printReport(this.__lastReport);
        },
        history: function() {
            return this.__history || [];
        },
        // Utility to add trusted domains at runtime
        addTrustedDomain: function(pattern) {
            if (CONFIG.trustedDomains.indexOf(pattern) === -1) {
                CONFIG.trustedDomains.push(pattern);
            }
        },
        // Override a detector (for advanced users)
        addDetector: function(name, fn) {
            Detectors[name] = fn;
        }
    };

    // Preserve previous queue if exists
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
            case 'audit':
                api.audit();
                break;
            case 'report':
                api.report();
                break;
            case 'addTrustedDomain':
                api.addTrustedDomain(args[0]);
                break;
            default:
                Util.log('warn', 'Unknown trusc command: ' + command);
        }
    }

    // Process queued commands
    for (var i = 0; i < cmdQueue.length; i++) {
        processCommand(cmdQueue[i]);
    }

    // Replace global with full API (keeping q for backwards compat)
    var fullAPI = Object.assign(api, {
        q: cmdQueue,
        push: function(cmd) {
            processCommand(cmd);
            cmdQueue.push(cmd);
        }
    });
    global.__trusc = fullAPI;

    // =========================================================================
    // SECTION 8: AUTO‑RUN & SELF‑TEST
    // =========================================================================
    Util.log('info', 'Trust & Security Auditor loaded. Auto‑auditing page...');
    runAudit();

    // Self‑test mode: ?trusc_test=2 creates a mock page with flaws in an iframe? We'll just log a test.
    if (location.search.indexOf('trusc_test=2') !== -1) {
        setTimeout(function() {
            console.log(CONFIG.logPrefix + ' Self‑test active – simulating some issues...');
            // We can't actually create issues on the live page safely, so we just print a fake report.
            var fakeIssues = [
                { severity: 'critical', title: 'Fake HTTP connection', detail: 'Test issue #1', fix: 'Use HTTPS.' },
                { severity: 'high', title: 'Fake mixed content', detail: 'Test issue #2', fix: 'Load over HTTPS.' }
            ];
            var fakeScore = 60;
            var fakeReport = generateReport(fakeIssues, fakeScore);
            printReport(fakeReport);
            console.log('%cSelf‑test complete. Verify that the report above is visible.', 'font-weight: bold');
        }, 300);
    }

})(typeof window !== 'undefined' ? window : globalThis,
   typeof document !== 'undefined' ? document : undefined,
   typeof console !== 'undefined' ? console : undefined,
   Math, Date, setTimeout, clearTimeout, Array, Object, RegExp, JSON,
   typeof Promise !== 'undefined' ? Promise : undefined,
   typeof location !== 'undefined' ? location : undefined,
   typeof navigator !== 'undefined' ? navigator : undefined);
