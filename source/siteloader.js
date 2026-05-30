/**
 * siteloader.js — Console-Only Edition (Enterprise Telemetry Engine v5.0.0)
 * --------------------------------------------------------------------------
 * @fileoverview Catches all frontend exceptions & unhandled rejections,
 *              applies advanced deduplication, buffers them, and mirrors
 *              beautifully formatted reports to the browser console.
 *              No GitHub token required – purely client-side.
 *
 * @author   Qweetlystudios DevOps Taskforce
 * @version  5.0.0 (console-only)
 * @license  MIT (just because)
 *
 * Usage: Drop it in <head> and every error will be logged with rich details.
 *        Supports the __siteloader command queue for manual reporting.
 */
(function(global, document, navigator, console, Math, Date, setTimeout, clearTimeout, Array, Object, RegExp, JSON, Promise) {
    'use strict';

    // =========================================================================
    // SECTION 1: IMMUTABLE CONFIGURATION
    // =========================================================================
    var CONFIG = {
        consoleLoggingVerbosity: 'high', // 'low', 'medium', 'high', 'insane'
        consoleLogPrefix: '🐞 [siteloader]',
        enableConsoleGrouping: true,
        maxTitleLen: 120,
        titleTruncationSuffix: ' [...]',
        dedupWindowMs: 60000,            // skip identical errors for 1 min
        bufferFlushIntervalMs: 3000,
        maxConsoleReportsPerFlush: 3,    // rate-limit the console flooding
        enableConsoleErrorMonkeyPatch: true,
        enableGlobalOnError: true,
        enableUnhandledRejection: true,
        enableAggressiveDeduplication: true,
        enableSignatureHashing: true      // use a quick hash for dedup
    };

    // =========================================================================
    // SECTION 2: UTILITY BELT
    // =========================================================================
    var Util = {
        djb2Hash: function(str) {
            var hash = 5381, i;
            for (i = 0; i < str.length; i++) {
                hash = ((hash << 5) + hash) + str.charCodeAt(i);
                hash = hash & hash; // 32-bit
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
        isDuplicate: function(signature, cache, windowMs) {
            var now = Date.now();
            if (cache.hasOwnProperty(signature)) {
                if ((now - cache[signature]) < windowMs) return true;
            }
            cache[signature] = now;
            return false;
        }
    };

    // =========================================================================
    // SECTION 4: CONSOLE FORMATTER (RICH OUTPUT)
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
    // SECTION 5: BATCH PROCESSOR (BUFFER & FLUSH TO CONSOLE)
    // =========================================================================
    var BufferProcessor = (function() {
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
                    console.debug(CONFIG.consoleLogPrefix + ' duplicate suppressed: ' + signature);
                }
                return;
            }

            buffer.push({ signature: signature, event: evt, timestamp: Date.now() });
            if (CONFIG.consoleLoggingVerbosity !== 'low') {
                console.debug(CONFIG.consoleLogPrefix + ' buffered (' + buffer.length + ')');
            }
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

            // Group if console.groupCollapsed exists
            if (CONFIG.enableConsoleGrouping && console.groupCollapsed) {
                console.groupCollapsed(CONFIG.consoleLogPrefix + ' Batch Report (' + batch.length + ' error(s))');
            }

            for (var i = 0; i < batch.length; i++) {
                var evt = batch[i].event;
                var header = ConsoleFormatter.buildHeader(evt.type, evt.message);
                var details = ConsoleFormatter.buildDetails(evt);
                console.error(header);
                console.log('  Details:', details);
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
    // SECTION 6: ERROR HOOKS
    // =========================================================================
    function installHooks() {
        // 1. window.onerror
        if (CONFIG.enableGlobalOnError) {
            var prevOnError = global.onerror;
            global.onerror = function(message, source, lineno, colno, error) {
                BufferProcessor.enqueue({
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
        }

        // 2. unhandledrejection
        if (CONFIG.enableUnhandledRejection) {
            global.addEventListener('unhandledrejection', function(event) {
                var reason = event.reason;
                var message = (reason && reason.message) ? reason.message : String(reason);
                var errorObj = reason instanceof Error ? reason : new Error(message);
                if (reason && reason.stack && !(reason instanceof Error)) {
                    try { errorObj.stack = reason.stack; } catch(e) {}
                }
                BufferProcessor.enqueue({
                    type: 'unhandledrejection',
                    message: message,
                    source: 'Promise',
                    lineno: 0,
                    colno: 0,
                    error: errorObj
                });
            });
        }

        // 3. console.error monkey-patch (optional)
        if (CONFIG.enableConsoleErrorMonkeyPatch) {
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
                        return typeof a === 'string' ? a : (typeof a === 'object' ? JSON.stringify(a) : String(a));
                    }).join(' ');
                    errorObj = null;
                }
                if (!firstArg || !firstArg.__siteloaderInternal) {
                    BufferProcessor.enqueue({
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
    }

    // =========================================================================
    // SECTION 7: COMMAND QUEUE (GOOGLE-STYLE)
    // =========================================================================
    var cmdQueue = [];
    if (global.__siteloader && Array.isArray(global.__siteloader)) {
        cmdQueue = global.__siteloader;
    } else if (global.__siteloader && global.__siteloader.q && Array.isArray(global.__siteloader.q)) {
        cmdQueue = global.__siteloader.q;
    }

    function processCommand(cmd) {
        if (!cmd || !Array.isArray(cmd)) return;
        if (cmd[0] === 'report') {
            var evt = cmd[1] || {};
            if (typeof evt !== 'object') evt = { message: String(evt) };
            evt.type = evt.type || 'manual';
            if (!evt.message) evt.message = 'Manual report';
            BufferProcessor.enqueue(evt);
        }
    }

    // Process existing queue
    for (var i = 0; i < cmdQueue.length; i++) {
        processCommand(cmdQueue[i]);
    }

    // Replace global __siteloader with push-enabled object
    var api = {
        q: cmdQueue,
        push: function(cmd) {
            processCommand(cmd);
            cmdQueue.push(cmd);
        }
    };
    global.__siteloader = api;

    // =========================================================================
    // SECTION 8: BOOT
    // =========================================================================
    installHooks();
    console.log(CONFIG.consoleLogPrefix + ' Console-only telemetry active. All errors stay local. No token needed.');

    // Optional self-test if URL param ?siteloader_test=1
    if (global.location && global.location.search.indexOf('siteloader_test') !== -1) {
        setTimeout(function() {
            throw new Error('siteloader.js console-only self-test error');
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
