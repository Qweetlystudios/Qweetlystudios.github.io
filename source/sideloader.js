/**
 * sideloader.js — Enterprise Resource Sideloader + Self‑Test
 * -----------------------------------------------------------
 * @fileoverview Dynamically loads scripts, styles, images, and JSON
 *              with caching, deduplication, retries, and timeouts.
 *              When the URL contains ?sideloader_test=2 it deliberately
 *              throws an error to verify the bug‑reporting chain.
 *
 * @author   Qweetlystudios DevOps Taskforce (Sideload Division)
 * @version  2.0.0 – with ?sideloader_test=2 self‑test
 *
 * Usage:
 *   __sideloader.require('lib.js');
 *   __sideloader.style('theme.css');
 *   __sideloader.image('logo.png');
 *   __sideloader.json('data.json', callback);
 *
 *   Add ?sideloader_test=2 to test the error‑reporting pipeline.
 */
(function(global, document, console, Math, Date, setTimeout, clearTimeout, Array, Object, JSON, Promise, fetch) {
    'use strict';

    // =========================================================================
    // CONFIGURATION
    // =========================================================================
    var SideloaderConfig = {
        logLevel: 'info',
        logPrefix: '📦 [sideloader]',
        defaults: {
            script: { async: true, defer: false, timeout: 15000 },
            style:  { rel: 'stylesheet', timeout: 10000 },
            image:  { timeout: 12000 },
            json:   { method: 'GET', timeout: 10000 }
        },
        maxRetries: 2,
        retryBaseMs: 1000,
        retryJitter: true,
        deduplicate: true,
        enableMemoryCache: true,
        cacheTTL: 3600000 // 1 hour
    };

    // =========================================================================
    // UTILITY BELT
    // =========================================================================
    var Util = {
        djb2Hash: function(str) {
            var hash = 5381, i;
            for (i = 0; i < str.length; i++) {
                hash = ((hash << 5) + hash) + str.charCodeAt(i);
                hash = hash & hash; // 32-bit
            }
            return 'res_' + (hash >>> 0);
        },
        escapeRegExp: function(string) {
            return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        },
        merge: function(target, source) {
            var result = {};
            for (var key in target) if (target.hasOwnProperty(key)) result[key] = target[key];
            for (var key in source) if (source.hasOwnProperty(key)) result[key] = source[key];
            return result;
        },
        isObject: function(val) {
            return val !== null && typeof val === 'object' && !Array.isArray(val);
        },
        createElement: function(tag, attrs, parent) {
            var el = document.createElement(tag);
            for (var key in attrs) if (attrs.hasOwnProperty(key) && attrs[key] != null) el.setAttribute(key, attrs[key]);
            if (parent) parent.appendChild(el);
            return el;
        },
        log: function(level, msg) {
            var levels = { 'silent':0, 'error':1, 'warn':2, 'info':3, 'debug':4, 'trace':5 };
            var cfgLevel = levels[SideloaderConfig.logLevel] || 3;
            if (levels[level] <= cfgLevel) {
                var args = [SideloaderConfig.logPrefix + ' ' + msg];
                for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
                if (level === 'error') console.error.apply(console, args);
                else if (level === 'warn') console.warn.apply(console, args);
                else console.info.apply(console, args);
            }
        },
        backoff: function(retryCount) {
            var base = SideloaderConfig.retryBaseMs * Math.pow(2, retryCount);
            if (SideloaderConfig.retryJitter) base += Math.floor(Math.random() * (base * 0.3));
            return base;
        }
    };

    // =========================================================================
    // RESOURCE CACHE & DEDUPLICATION
    // =========================================================================
    var ResourceCache = (function() {
        var cache = {};
        var pending = {};

        function get(url) {
            if (!SideloaderConfig.enableMemoryCache) return null;
            var entry = cache[url];
            if (!entry) return null;
            if (SideloaderConfig.cacheTTL > 0 && (Date.now() - entry.timestamp) > SideloaderConfig.cacheTTL) {
                delete cache[url];
                return null;
            }
            entry.loadCount = (entry.loadCount || 0) + 1;
            return entry.value;
        }

        function set(url, value, type) {
            if (SideloaderConfig.enableMemoryCache) cache[url] = { type:type, value:value, timestamp:Date.now(), loadCount:0 };
        }

        function getPending(url) { return SideloaderConfig.deduplicate ? pending[url] : null; }
        function setPending(url, promise) { if (SideloaderConfig.deduplicate) pending[url] = promise; }
        function clearPending(url) { if (pending[url]) delete pending[url]; }

        return { get:get, set:set, getPending:getPending, setPending:setPending, clearPending:clearPending };
    })();

    // =========================================================================
    // CORE LOADER FUNCTIONS
    // =========================================================================
    var Loader = {
        script: function(url, options) {
            var opts = Util.merge(SideloaderConfig.defaults.script, options || {});
            return new Promise(function(resolve, reject) {
                var cached = ResourceCache.get(url);
                if (cached) { Util.log('info', 'Cached script: ' + url); resolve(cached); return; }
                var pending = ResourceCache.getPending(url);
                if (pending) { pending.then(resolve, reject); return; }

                var loadPromise = new Promise(function(innerResolve, innerReject) {
                    var timeoutId = opts.timeout ? setTimeout(function() {
                        var err = new Error('Timeout loading script: ' + url);
                        Util.log('error', err.message);
                        cleanup();
                        innerReject(err);
                    }, opts.timeout) : null;
                    function cleanup() { if (timeoutId) clearTimeout(timeoutId); ResourceCache.clearPending(url); }
                    var el = Util.createElement('script', { src:url, async:opts.async?'true':null, defer:opts.defer?'true':null, crossorigin:opts.crossorigin, integrity:opts.integrity, type:opts.type }, document.head);
                    el.onload = function() { cleanup(); Util.log('info', 'Script loaded: ' + url); ResourceCache.set(url, el, 'script'); innerResolve(el); };
                    el.onerror = function(e) { cleanup(); var err = new Error('Failed to load script: ' + url); Util.log('error', err.message, e); if(el.parentNode) el.parentNode.removeChild(el); innerReject(err); };
                });
                ResourceCache.setPending(url, loadPromise);
                loadPromise.then(resolve, reject);
            });
        },
        style: function(url, options) {
            var opts = Util.merge(SideloaderConfig.defaults.style, options || {});
            return new Promise(function(resolve, reject) {
                var cached = ResourceCache.get(url);
                if (cached) { Util.log('info', 'Cached style: ' + url); resolve(cached); return; }
                var pending = ResourceCache.getPending(url);
                if (pending) { pending.then(resolve, reject); return; }

                var loadPromise = new Promise(function(innerResolve, innerReject) {
                    var timeoutId = opts.timeout ? setTimeout(function() {
                        var err = new Error('Timeout loading style: ' + url);
                        Util.log('error', err.message);
                        cleanup();
                        innerReject(err);
                    }, opts.timeout) : null;
                    function cleanup() { if (timeoutId) clearTimeout(timeoutId); ResourceCache.clearPending(url); }
                    var el = Util.createElement('link', { rel:opts.rel||'stylesheet', href:url, crossorigin:opts.crossorigin, integrity:opts.integrity }, document.head);
                    el.onload = function() { cleanup(); Util.log('info', 'Style loaded: ' + url); ResourceCache.set(url, el, 'style'); innerResolve(el); };
                    el.onerror = function(e) { cleanup(); var err = new Error('Failed to load style: ' + url); Util.log('error', err.message, e); if(el.parentNode) el.parentNode.removeChild(el); innerReject(err); };
                });
                ResourceCache.setPending(url, loadPromise);
                loadPromise.then(resolve, reject);
            });
        },
        image: function(url, options) {
            var opts = Util.merge(SideloaderConfig.defaults.image, options || {});
            return new Promise(function(resolve, reject) {
                var cached = ResourceCache.get(url);
                if (cached) { Util.log('info', 'Cached image: ' + url); resolve(cached); return; }
                var pending = ResourceCache.getPending(url);
                if (pending) { pending.then(resolve, reject); return; }

                var loadPromise = new Promise(function(innerResolve, innerReject) {
                    var img = new Image();
                    var timeoutId = opts.timeout ? setTimeout(function() {
                        var err = new Error('Timeout loading image: ' + url);
                        Util.log('error', err.message);
                        cleanup();
                        innerReject(err);
                        img.src = '';
                    }, opts.timeout) : null;
                    function cleanup() { if (timeoutId) clearTimeout(timeoutId); ResourceCache.clearPending(url); img.onload = img.onerror = null; }
                    img.onload = function() { cleanup(); Util.log('info', 'Image loaded: ' + url); ResourceCache.set(url, img, 'image'); innerResolve(img); };
                    img.onerror = function(e) { cleanup(); var err = new Error('Failed to load image: ' + url); Util.log('error', err.message, e); innerReject(err); };
                    img.src = url;
                });
                ResourceCache.setPending(url, loadPromise);
                loadPromise.then(resolve, reject);
            });
        },
        json: function(url, options) {
            var opts = Util.merge({ method:'GET', timeout:SideloaderConfig.defaults.json.timeout }, options || {});
            return new Promise(function(resolve, reject) {
                var cached = ResourceCache.get(url);
                if (cached) { Util.log('info', 'Cached JSON: ' + url); resolve(cached); return; }
                var pending = ResourceCache.getPending(url);
                if (pending) { pending.then(resolve, reject); return; }

                var loadPromise = new Promise(function(innerResolve, innerReject) {
                    var controller = new AbortController();
                    var timeoutId = opts.timeout ? setTimeout(function() { controller.abort(); var err = new Error('Timeout fetching JSON: ' + url); Util.log('error', err.message); innerReject(err); }, opts.timeout) : null;
                    fetch(url, { method:opts.method, headers:opts.headers||{}, signal:controller.signal })
                        .then(function(response) { if(!response.ok) throw new Error('HTTP ' + response.status + ' for ' + url); return response.json(); })
                        .then(function(data) { if(timeoutId) clearTimeout(timeoutId); ResourceCache.clearPending(url); Util.log('info', 'JSON loaded: ' + url); ResourceCache.set(url, data, 'json'); innerResolve(data); })
                        .catch(function(err) { if(timeoutId) clearTimeout(timeoutId); ResourceCache.clearPending(url); Util.log('error', 'Failed to load JSON: ' + url, err); innerReject(err); });
                });
                ResourceCache.setPending(url, loadPromise);
                loadPromise.then(resolve, reject);
            });
        }
    };

    // =========================================================================
    // RETRY WRAPPER
    // =========================================================================
    function withRetry(loaderFn, url, options) {
        var maxRetries = (options && options.maxRetries !== undefined) ? options.maxRetries : SideloaderConfig.maxRetries;
        var attempts = 0;
        return new Promise(function(resolve, reject) {
            function attempt() {
                loaderFn(url, options).then(resolve).catch(function(err) {
                    attempts++;
                    if (attempts <= maxRetries) {
                        var delay = Util.backoff(attempts);
                        Util.log('warn', 'Retrying ' + url + ' in ' + delay + 'ms (' + attempts + '/' + maxRetries + ')');
                        setTimeout(attempt, delay);
                    } else {
                        Util.log('error', 'All retries exhausted for ' + url, err);
                        reject(err);
                    }
                });
            }
            attempt();
        });
    }

    // =========================================================================
    // HIGH‑LEVEL API
    // =========================================================================
    var SideloaderAPI = {
        load: function(resources, callback) {
            var single = !Array.isArray(resources);
            if (single) resources = [resources];
            var promises = resources.map(function(res) {
                if (typeof res === 'string') return withRetry(Loader.script, res);
                if (typeof res === 'object') {
                    var type = res.type || 'script';
                    var url = res.url;
                    if (!url) return Promise.reject(new Error('Resource missing url'));
                    switch (type) {
                        case 'script': return withRetry(Loader.script, url, res);
                        case 'style':  return withRetry(Loader.style, url, res);
                        case 'image':  return withRetry(Loader.image, url, res);
                        case 'json':   return withRetry(Loader.json, url, res);
                        default:        return Promise.reject(new Error('Unknown type: ' + type));
                    }
                }
                return Promise.reject(new Error('Invalid resource'));
            });
            var resultPromise = single ? promises[0] : Promise.all(promises);
            if (typeof callback === 'function') {
                resultPromise.then(function(r) { callback(null, r); }, function(e) { callback(e); });
            } else {
                return resultPromise;
            }
        },
        require: function(urls, callback) {
            if (!Array.isArray(urls)) urls = [urls];
            return this.load(urls.map(function(u) { return { type:'script', url:u }; }), callback);
        },
        style: function(url, optionsOrCallback) {
            var options = {}, callback;
            if (typeof optionsOrCallback === 'function') callback = optionsOrCallback;
            else options = optionsOrCallback || {};
            return this.load({ type:'style', url:url }, callback);
        },
        image: function(url, optionsOrCallback) {
            var options = {}, callback;
            if (typeof optionsOrCallback === 'function') callback = optionsOrCallback;
            else options = optionsOrCallback || {};
            return this.load({ type:'image', url:url }, callback);
        },
        json: function(url, optionsOrCallback) {
            var options = {}, callback;
            if (typeof optionsOrCallback === 'function') callback = optionsOrCallback;
            else options = optionsOrCallback || {};
            return this.load({ type:'json', url:url }, callback);
        }
    };

    // =========================================================================
    // COMMAND QUEUE (Google Analytics style)
    // =========================================================================
    var commandQueue = [];
    if (global.__sideloader && Array.isArray(global.__sideloader)) {
        commandQueue = global.__sideloader;
    } else if (global.__sideloader && global.__sideloader.q && Array.isArray(global.__sideloader.q)) {
        commandQueue = global.__sideloader.q;
    }

    function processCommand(cmd) {
        if (!cmd || !Array.isArray(cmd)) return;
        var command = cmd[0];
        var args = Array.prototype.slice.call(cmd, 1);
        switch (command) {
            case 'require': SideloaderAPI.require.apply(SideloaderAPI, args); break;
            case 'style':   SideloaderAPI.style.apply(SideloaderAPI, args); break;
            case 'image':   SideloaderAPI.image.apply(SideloaderAPI, args); break;
            case 'json':    SideloaderAPI.json.apply(SideloaderAPI, args); break;
            case 'load':    SideloaderAPI.load(args[0], args[1]); break;
            default:        Util.log('warn', 'Unknown command: ' + command);
        }
    }

    for (var i = 0; i < commandQueue.length; i++) processCommand(commandQueue[i]);

    var publicAPI = {
        q: commandQueue,
        push: processCommand,
        load: SideloaderAPI.load,
        require: SideloaderAPI.require,
        style: SideloaderAPI.style,
        image: SideloaderAPI.image,
        json: SideloaderAPI.json
    };
    global.__sideloader = publicAPI;

    // =========================================================================
    // SELF‑TEST TRIGGERED BY ?sideloader_test=2
    // =========================================================================
    function runSelfTest() {
        if (!global.location || global.location.search.indexOf('sideloader_test=2') === -1) return;
        Util.log('info', '🔍 SELF‑TEST MODE ACTIVE – will throw a deliberate error in 1 second...');
        setTimeout(function() {
            // This error will be caught by siteloader.js if present, or shown in the console
            throw new Error('Self-test failed: deliberate error to verify bug reporting pipeline.');
        }, 1000);
    }

    // =========================================================================
    // INITIALIZATION
    // =========================================================================
    Util.log('info', 'Sideloader engine ready.');
    runSelfTest(); // Check URL and fire test if needed

})(typeof window !== 'undefined' ? window : globalThis,
   typeof document !== 'undefined' ? document : undefined,
   typeof console !== 'undefined' ? console : undefined,
   Math, Date, setTimeout, clearTimeout, Array, Object, JSON,
   typeof Promise !== 'undefined' ? Promise : undefined,
   typeof fetch !== 'undefined' ? fetch : undefined);
