/**
 * siteloader.js — Console‑Only Bug Catcher + Manual ?Bug=Fix Logger
 * ------------------------------------------------------------------
 * ✅ Automatically detects & logs all "wrongly coded code":
 *      - Runtime errors (ReferenceError, TypeError, etc.)
 *      - Unhandled Promise rejections
 *      - Explicit console.error() calls
 *      - (and deduplicates them so the console stays clean)
 *
 * ✅ Manual bug reporting via URL:
 *      ?Dark mode broken=Toggle does nothing
 *      → Prints a highlighted report to the console
 *
 * @usage   Drop in <head>. Use ?title=description to log a manual report.
 *          No token needed – everything stays inside the browser.
 */
(function(global, document, navigator, console, Math, Date, setTimeout, clearTimeout, Array, Object, RegExp, JSON, Promise) {
    'use strict';

    // =========================================================================
    // CONFIGURATION
    // =========================================================================
    var CONFIG = {
        consoleLoggingVerbosity: 'high',            // low|medium|high|insane
        consoleLogPrefix: '🐞 [siteloader]',
        enableConsoleGrouping: true,
        maxTitleLen: 120,
        titleTruncationSuffix: ' [...]',
        dedupWindowMs: 60000,                       // suppress identical errors for 1 minute
        bufferFlushIntervalMs: 3000,
        maxConsoleReportsPerFlush: 3
    };

    // =========================================================================
    // UTILITY BELT
    // =========================================================================
    var Util = {
        djb2Hash: function(str) {
            var hash = 5381, i;
            for (i = 0; i < str.length; i++) {
                hash = ((hash << 5) + hash) + str.charCodeAt(i);
                hash = hash & hash;
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
        getViewport: function() {
            try { return global.innerWidth + '×' + global.innerHeight; } catch(e) { return '?'; }
        },
        safeStringify: function(obj) {
            try { return JSON.stringify(obj); } catch(e) { return '[unserializable]'; }
        }
    };

    // =========================================================================
    // SIGNATURE ENGINE (DEDUPLICATION)
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
    // CONSOLE FORMATTER
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
    // CONSOLE BATCH PROCESSOR (BUFFERED FLUSH)
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
            if (SignatureEngine.isDuplicate(signature, signatureCache, CONFIG.dedupWindowMs)) {
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
    // URL PARSER: ?Title=Description → Console Manual Report
    // =========================================================================
    function processUrlManualReport() {
        if (!global.location || !global.location.search) return;
        var search = global.location.search.substring(1);
        if (search.length === 0) return;

        var pairs = search.split('&');
        for (var i = 0; i < pairs.length; i++) {
            var pair = pairs[i];
            if (!pair) continue;

            var eqIndex = pair.indexOf('=');
            var key, value;
            if (eqIndex >= 0) {
                key = decodeURIComponent(pair.substring(0, eqIndex).replace(/\+/g, ' ')).trim();
                value = decodeURIComponent(pair.substring(eqIndex + 1).replace(/\+/g, ' ')).trim();
            } else {
                key = decodeURIComponent(pair.replace(/\+/g, ' ')).trim();
                value = '';
            }

            if (!key) continue;
            if (key === 'siteloader_test') continue; // internal test

            // Prevent duplicate firing
            if (global.__siteloaderManualIssueFired) return;
            global.__siteloaderManualIssueFired = true;

            // Highlighted manual bug report (detected “wrongly coded code” from URL)
            console.log('%c' + CONFIG.consoleLogPrefix + ' MANUAL REPORT (from URL)',
                        'font-size: 1.2em; background: #ff0; color: #000; padding: 4px 8px;');
            console.log('🔧 Bug: ' + Util.truncate(key, CONFIG.maxTitleLen));
            console.log('📝 Fix: ' + (value || '(no description)'));
            console.log('📄 Page: ' + global.location.href);
            console.log('🕒 Time: ' + Util.formatTimestamp(new Date()));

            break; // only the first meaningful parameter
        }
    }

    // =========================================================================
    // ERROR HOOKS (detects all JavaScript coding mistakes)
    // =========================================================================
    function installErrorHooks() {
        // 1. Runtime errors (e.g., undefined variables, type errors)
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

        // 2. Unhandled Promise rejections (async coding mistakes)
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

        // 3. Explicit console.error() calls (often used to flag “wrong” code paths)
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
    // COMMAND QUEUE (__siteloader)
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
        }
    }

    for (var i = 0; i < commandQueue.length; i++) {
        processCommand(commandQueue[i]);
    }

    // Replace global __siteloader with push‑enabled object
    var api = {
        q: commandQueue,
        push: function(cmd) {
            processCommand(cmd);
            commandQueue.push(cmd);
        }
    };
    global.__siteloader = api;

    // =========================================================================
    // BOOT
    // =========================================================================
    installErrorHooks();                // start catching all coding mistakes
    processUrlManualReport();           // check for ?Bug title=Fix description

    console.log(CONFIG.consoleLogPrefix + ' Console‑only telemetry active. ' +
                'Automatic error detection ON. Use ?Bug=Fix to log manual reports.');

    // Self‑test (optional)
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
   typeof Promise !== 'undefined' ? Promise : undefined);
