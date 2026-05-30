/**
 * siteloader.js — Console‑Only + Manual GitHub Issue via URL (Enterprise v6.0.0)
 * ------------------------------------------------------------------------------
 * @fileoverview The ultimate telemetry engine: all frontend errors are mirrored
 *              to the browser console with zero external requests. Additionally,
 *              a `?issue=Your bug description` query parameter triggers a
 *              one‑time GitHub issue creation (requires a token).
 *
 * @author   Qweetlystudios DevOps Taskforce (Bot Division)
 * @version  6.0.0 (console‑first, URL‑triggered issue posting)
 *
 * @usage    Drop in <head>. For console‑only use: no configuration needed.
 *           For manual issue posting: set GITHUB_TOKEN and visit
 *           https://yoursite.com/?issue=Login button not working
 *
 * COMMANDS  (via the __siteloader queue):
 *   window.__siteloader.push(['report', { message: 'My bug', error: e }]);
 *   (Works before or after script load, just like Google Analytics.)
 */
(function(global, document, navigator, console, Math, Date, setTimeout, clearTimeout, Array, Object, RegExp, JSON, Promise, fetch) {
    'use strict';

    // =========================================================================
    // SECTION 1: HARDCODED CONFIGURATION
    // =========================================================================
    var CONFIG = {
        // ----- console‑only behaviour (always active) -----
        consoleLoggingVerbosity: 'high',            // low|medium|high|insane
        consoleLogPrefix: '🐞 [siteloader]',
        enableConsoleGrouping: true,
        maxTitleLen: 120,
        titleTruncationSuffix: ' [...]',
        dedupWindowMs: 60000,                       // suppress duplicates for 1 min
        bufferFlushIntervalMs: 3000,
        maxConsoleReportsPerFlush: 3,

        // ----- manual GitHub issue posting (via ?issue=) -----
        // Set this to a valid token for the bot account. Leave '' to disable.
        githubToken: '',                            // ← REPLACE with your token if using ?issue=
        repoOwner: 'Qweetlystudios',
        repoName: 'Qweetlystudios.github.io',
        issueLabels: ['bug', 'manually-reported'],
        maxRetries: 3,
        retryBaseMs: 1000,
        enableJitter: true
    };

    // Derived full API URL
    var API_URL = 'https://api.github.com/repos/' +
                  CONFIG.repoOwner + '/' + CONFIG.repoName + '/issues';

    // =========================================================================
    // SECTION 2: ULTIMATE UTILITY BELT
    // =========================================================================
    var Util = {
        djb2Hash: function(str) {
            var hash = 5381, i;
            for (i = 0; i < str.length; i++) {
                hash = ((hash << 5) + hash) + str.charCodeAt(i);
                hash = hash & hash; // 32‑bit
            }
            return hash;
        },
        pad: function(n, width) {
            var s = String(n);
            while (s.length < width) s = '0' + s;
            return s;
        },
        formatTimestamp: function(date) {
            if (!date || !(date instanceof Date)) date = new Date();
            return date.getFullYear() + '-' +
                   Util.pad(date.getMonth()+1,2) + '-' +
                   Util.pad(date.getDate(),2) + ' ' +
                   Util.pad(date.getHours(),2) + ':' +
                   Util.pad(date.getMinutes(),2) + ':' +
                   Util.pad(date.getSeconds(),2) + '.' +
                   Util.pad(date.getMilliseconds(),3);
        },
        truncate: function(str, maxLen, suffix) {
            str = String(str);
            if (str.length <= maxLen) return str;
            suffix = suffix || '...';
            return str.substring(0, maxLen - suffix.length) + suffix;
        },
        jitter: function(maxMs) {
            return Math.floor(Math.random() * (maxMs + 1));
        },
        getViewport: function() {
            try { return global.innerWidth + '×' + global.innerHeight; } catch(e) { return '?'; }
        },
        safeStringify: function(obj) {
            try { return JSON.stringify(obj); } catch(e) { return '[unserializable]'; }
        }
    };

    // =========================================================================
    // SECTION 3: SIGNATURE ENGINE (DEDUPLICATION)
    // =========================================================================
    var SignatureEngine = {
        generate: function(message, source, stack) {
            var raw = String(message) + '|' + String(source) + '|' + String(stack).substring(0, 500);
            return 'sig:' + Util.djb2Hash(raw);
        },
        isDuplicate: function(sig, cache, windowMs) {
            var now = Date.now();
            if (cache.hasOwnProperty(sig) && (now - cache[sig]) < windowMs) {
                return true;
            }
            cache[sig] = now;
            return false;
        }
    };

    // =========================================================================
    // SECTION 4: CONSOLE FORMATTER (RICH ERROR OUTPUT)
    // =========================================================================
    var ConsoleFormatter = {
        buildHeader: function(type, message) {
            var clean = Util.truncate(String(message || 'Unknown error').replace(/\n/g, ' '),
                                       CONFIG.maxTitleLen, CONFIG.titleTruncationSuffix);
            return '🛑 ' + type + ': ' + clean;
        },
        buildDetails: function(evt) {
            return {
                message: evt.message,
                source: evt.source || '?',
                location: (evt.lineno||'?') + ':' + (evt.colno||'?'),
                pageUrl: (global.location ? global.location.href : 'N/A'),
                viewport: Util.getViewport(),
                userAgent: (navigator.userAgent || 'Unknown'),
                timestamp: Util.formatTimestamp(new Date()),
                stack: (evt.error && evt.error.stack) ? evt.error.stack : 'No stack trace'
            };
        }
    };

    // =========================================================================
    // SECTION 5: CONSOLE BATCH PROCESSOR (BUFFER → CONSOLE)
    // =========================================================================
    var ConsoleBatchProcessor = (function() {
        var buffer = [];
        var signatureCache = {};
        var flushTimer = null;
        var isProcessing = false;

        function enqueue(evt) {
            var signature = SignatureEngine.generate(
                evt.message, evt.source,
                (evt.error && evt.error.stack) || ''
            );
            if (CONFIG.enableAggressiveDeduplication &&
                SignatureEngine.isDuplicate(signature, signatureCache, CONFIG.dedupWindowMs)) {
                if (CONFIG.consoleLoggingVerbosity === 'insane') {
                    console.debug(CONFIG.consoleLogPrefix + ' duplicate suppressed (' + signature + ')');
                }
                return;
            }
            buffer.push({ signature: signature, event: evt, timestamp: Date.now() });
            scheduleFlush();
        }

        function scheduleFlush() {
            if (flushTimer) clearTimeout(flushTimer);
            flushTimer = setTimeout(flushToConsole, CONFIG.bufferFlushIntervalMs);
        }

        function flushToConsole() {
            flushTimer = null;
            if (buffer.length === 0 || isProcessing) return;
            isProcessing = true;
            var batch = buffer.splice(0, CONFIG.maxConsoleReportsPerFlush);

            if (CONFIG.enableConsoleGrouping && console.groupCollapsed) {
                console.groupCollapsed(CONFIG.consoleLogPrefix + ' Batch Report (' + batch.length + ' error(s))');
            }

            for (var i = 0; i < batch.length; i++) {
                var evt = batch[i].event;
                console.error(ConsoleFormatter.buildHeader(evt.type, evt.message));
                console.log('  Details:', ConsoleFormatter.buildDetails(evt));
            }

            if (CONFIG.enableConsoleGrouping && console.groupEnd) {
                console.groupEnd();
            }
            isProcessing = false;
            if (buffer.length > 0) scheduleFlush();
        }

        return { enqueue: enqueue, flush: flushToConsole, getBufferLength: function() { return buffer.length; } };
    })();

    // =========================================================================
    // SECTION 6: GITHUB ISSUE CREATION (USED ONLY FOR MANUAL REPORTS)
    // =========================================================================
    var GitHubManualReporter = {
        /**
         * Posts a single issue to GitHub with retries.
         * @param {string} title
         * @param {string} body
         * @returns {Promise}
         */
        create: function(title, body) {
            if (!CONFIG.githubToken) {
                console.warn(CONFIG.consoleLogPrefix + ' No GitHub token set – cannot create issue. Title: ' + title);
                return Promise.reject(new Error('No token'));
            }

            return new Promise(function(resolve, reject) {
                var attempt = function(retriesLeft) {
                    var headers = {
                        'Authorization': 'token ' + CONFIG.githubToken,
                        'Content-Type': 'application/json',
                        'Accept': 'application/vnd.github.v3+json'
                    };
                    var payload = {
                        title: title,
                        body: body,
                        labels: CONFIG.issueLabels
                    };

                    fetch(API_URL, {
                        method: 'POST',
                        headers: headers,
                        body: JSON.stringify(payload)
                    })
                    .then(function(response) {
                        if (!response.ok) throw new Error('HTTP ' + response.status + ' ' + response.statusText);
                        return response.json();
                    })
                    .then(resolve)
                    .catch(function(err) {
                        if (retriesLeft <= 0) return reject(err);
                        var backoff = CONFIG.retryBaseMs * Math.pow(2, CONFIG.maxRetries - retriesLeft);
                        if (CONFIG.enableJitter) backoff += Util.jitter(backoff * 0.3);
                        console.warn(CONFIG.consoleLogPrefix + ' Retrying issue in ' + backoff + 'ms (' + retriesLeft + ' left)');
                        setTimeout(function() { attempt(retriesLeft - 1); }, backoff);
                    });
                };
                attempt(CONFIG.maxRetries);
            });
        }
    };

    // =========================================================================
    // SECTION 7: URL‑TRIGGERED MANUAL ISSUE (`?issue=description`)
    // =========================================================================
    function checkUrlForManualIssue() {
        if (!global.location || !global.location.search) return;
        var params = new URLSearchParams(global.location.search);
        var issueText = params.get('issue');
        if (!issueText || issueText.trim() === '') return;

        // Prevent duplicate posting on the same page load
        if (global.__siteloaderManualIssueFired) return;
        global.__siteloaderManualIssueFired = true;

        var title = 'Manual report: ' + Util.truncate(issueText.trim(), CONFIG.maxTitleLen);
        var body = [
            '**Manual bug report from URL parameter**',
            '',
            '**Reported issue:** ' + issueText,
            '**Page URL:** ' + global.location.href,
            '**User Agent:** ' + (navigator.userAgent || 'Unknown'),
            '**Viewport:** ' + Util.getViewport(),
            '**Timestamp:** ' + Util.formatTimestamp(new Date())
        ].join('\n');

        if (CONFIG.githubToken) {
            console.log(CONFIG.consoleLogPrefix + ' Creating GitHub issue from ?issue= parameter...');
            GitHubManualReporter.create(title, body).then(function(issue) {
                console.log(CONFIG.consoleLogPrefix + ' ✅ Issue created: #' + issue.number + ' ' + issue.html_url);
            }).catch(function(err) {
                console.error(CONFIG.consoleLogPrefix + ' ❌ Failed to create issue:', err);
                // Fallback: log to console
                console.log('Would have posted:\n' + title + '\n' + body);
            });
        } else {
            // No token, just log prominently
            console.log('%c' + CONFIG.consoleLogPrefix + ' MANUAL ISSUE (no token)',
                        'font-size: 1.2em; background: #ff0; color: #000');
            console.log(title);
            console.log(body);
        }
    }

    // =========================================================================
    // SECTION 8: ERROR HOOKS (always active, console‑only)
    // =========================================================================
    function installErrorHooks() {
        // window.onerror
        var prevOnError = global.onerror;
        global.onerror = function(message, source, lineno, colno, error) {
            ConsoleBatchProcessor.enqueue({
                type: 'onerror',
                message: String(message),
                source: String(source),
                lineno: lineno,
                colno: colno,
                error: error
            });
            if (typeof prevOnError === 'function') {
                return prevOnError.apply(this, arguments);
            }
            return false;
        };

        // unhandledrejection
        global.addEventListener('unhandledrejection', function(event) {
            var reason = event.reason;
            var message = (reason && reason.message) ? reason.message : String(reason);
            var errorObj = reason instanceof Error ? reason : new Error(message);
            if (reason && reason.stack && !(reason instanceof Error)) {
                try { errorObj.stack = reason.stack; } catch(e) {}
            }
            ConsoleBatchProcessor.enqueue({
                type: 'unhandledrejection',
                message: message,
                source: 'Promise',
                lineno: 0,
                colno: 0,
                error: errorObj
            });
        });

        // console.error monkey‑patch (optional)
        var origConsoleError = console.error;
        console.error = function() {
            origConsoleError.apply(console, arguments);
            var firstArg = arguments[0];
            var message, errorObj;
            if (firstArg instanceof Error) {
                message = firstArg.message;
                errorObj = firstArg;
            } else {
                message = Array.prototype.slice.call(arguments).map(function(a) {
                    return typeof a === 'string' ? a : Util.safeStringify(a);
                }).join(' ');
                errorObj = null;
            }
            if (!firstArg || !firstArg.__siteloaderInternal) {
                ConsoleBatchProcessor.enqueue({
                    type: 'console.error',
                    message: message,
                    source: 'console.error',
                    lineno: 0,
                    colno: 0,
                    error: errorObj
                });
            }
        };
    }

    // =========================================================================
    // SECTION 9: COMMAND QUEUE (GOOGLE ANALYTICS STYLE)
    // =========================================================================
    var commandQueue = [];
    if (global.__siteloader && Array.isArray(global.__siteloader)) {
        commandQueue = global.__siteloader;
    } else if (global.__siteloader && global.__siteloader.q && Array.isArray(global.__siteloader.q)) {
        commandQueue = global.__siteloader.q;
    }

    function processCommand(cmd) {
        if (!cmd || !Array.isArray(cmd)) return;
        if (cmd[0] === 'report') {
            var evt = cmd[1] || {};
            if (typeof evt !== 'object') evt = { message: String(evt) };
            evt.type = evt.type || 'manual';
            if (!evt.message) evt.message = 'Manual report';
            ConsoleBatchProcessor.enqueue(evt);

            // Also optionally create a GitHub issue if token is provided and user explicitly asks for it
            // (we could add a flag, but for now manual reports stay console-only)
            if (evt.createIssue && CONFIG.githubToken) {
                var title = 'Manual console report: ' + Util.truncate(evt.message, CONFIG.maxTitleLen);
                var body = '**Manual report from console.**\n\n' +
                           'Message: ' + evt.message + '\n\n' +
                           'Page: ' + global.location.href;
                GitHubManualReporter.create(title, body);
            }
        }
    }

    // Process any previously queued commands
    for (var i = 0; i < commandQueue.length; i++) {
        processCommand(commandQueue[i]);
    }

    // Replace global __siteloader with a push‑enabled object
    var api = {
        q: commandQueue,
        push: function(cmd) {
            processCommand(cmd);
            commandQueue.push(cmd);
        }
    };
    global.__siteloader = api;

    // =========================================================================
    // SECTION 10: BOOT SEQUENCE
    // =========================================================================
    installErrorHooks();
    checkUrlForManualIssue();       // process any ?issue= right away

    console.log(CONFIG.consoleLogPrefix + ' Console‑only telemetry active. ' +
                (CONFIG.githubToken ? 'Manual GitHub issue posting enabled via ?issue=.' :
                                      'No GitHub token – ?issue= will log to console.'));

    // Self‑test if ?siteloader_test=1
    if (global.location && global.location.search.indexOf('siteloader_test') !== -1) {
        setTimeout(function() {
            throw new Error('siteloader.js self-test error');
        }, 100);
    }

})(typeof window !== 'undefined' ? window : globalThis,
   typeof document !== 'undefined' ? document : undefined,
   typeof navigator !== 'undefined' ? navigator : undefined,
   typeof console !== 'undefined' ? console : undefined,
   Math,
   Date,
   setTimeout,
   clearTimeout,
   Array,
   Object,
   RegExp,
   typeof JSON !== 'undefined' ? JSON : undefined,
   typeof Promise !== 'undefined' ? Promise : undefined,
   typeof fetch !== 'undefined' ? fetch : undefined);
