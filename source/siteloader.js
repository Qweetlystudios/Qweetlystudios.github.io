(function (globalWindow) {
    "use strict";

    var TARGET_DESTINATION_REPOS_URL = "https://github.com";
    var SYSTEM_SESSION_TOKEN = "QW-" + Date.now().toString(36).toUpperCase() + "-" + Math.floor(Math.random() * 89999 + 10000);
    
    var diagnosticRegisterLogs = [];
    var executionLockdownActive = false;
    var totalTriggeredSystemFaults = 0;

    function internalLoggerBufferAppend(logLevel, subsystemCode, textMessage) {
        var logPayloadItem = {
            timestamp: new Date().toISOString(),
            level: logLevel,
            subsystem: subsystemCode,
            message: textMessage
        };
        diagnosticRegisterLogs.push(logPayloadItem);
        if (diagnosticRegisterLogs.length > 250) {
            diagnosticRegisterLogs.shift();
        }
    }

    function dispatchPayloadReportToGitHub(vandalismType, rawErrorMessage, stackDetailTrace) {
        totalTriggeredSystemFaults++;
        
        var structuredIssueTitle = "[BUG DETECTED] [" + SYSTEM_SESSION_TOKEN + "] - " + vandalismType;
        
        var payloadBuilderText = "";
        payloadBuilderText += "### Qweetly Studios Runtime Diagnostic Log\n\n";
        payloadBuilderText += "* **Session Identity Marker:** `" + SYSTEM_SESSION_TOKEN + "`\n";
        payloadBuilderText += "* **Violation Threat Level:** CRITICAL RUNTIME EXCEPTION\n";
        payloadBuilderText += "* **Local Timestamp:** " + new Date().toString() + "\n";
        payloadBuilderText += "* **User Agent Vector:** " + (globalWindow.navigator ? globalWindow.navigator.userAgent : "Unknown Node Environment") + "\n\n";
        payloadBuilderText += "#### Exception Summary:\n";
        payloadBuilderText += "```text\n" + rawErrorMessage + "\n```\n\n";
        payloadBuilderText += "#### Target Stack Trace Traversal:\n";
        payloadBuilderText += "```javascript\n" + (stackDetailTrace || "No deep execution stack frames extracted from target context framework.") + "\n```\n\n";
        payloadBuilderText += "#### Internal Buffer Dump:\n```json\n";
        payloadBuilderText += JSON.stringify(diagnosticRegisterLogs, null, 2);
        payloadBuilderText += "\n```\n\n";
        payloadBuilderText += "--- \n_Report dynamically compiled and dispatched by `siteloader.js` core watchdog subsystem engine._";

        var formattedRedirectURI = TARGET_DESTINATION_REPOS_URL + 
            "?title=" + encodeURIComponent(structuredIssueTitle) + 
            "&body=" + encodeURIComponent(payloadBuilderText);
        
        internalLoggerBufferAppend("FATAL", "WATCHDOG", "Redirecting active viewport thread to issue dispatcher system link.");
        
        if (globalWindow.open) {
            globalWindow.open(formattedRedirectURI, "_blank");
        } else {
            globalWindow.location.href = formattedRedirectURI;
        }
    }

    function injectStatusElementToDOM() {
        internalLoggerBufferAppend("INFO", "DOM_ENGINE", "Attempting interface element generation.");
        var domDocumentInstance = globalWindow.document;
        
        if (!domDocumentInstance || !domDocumentInstance.body) {
            internalLoggerBufferAppend("ERROR", "DOM_ENGINE", "Target document body is not ready for child appends.");
            return false;
        }

        try {
            var validationDivElement = domDocumentInstance.createElement("div");
            validationDivElement.id = "load-status";
            validationDivElement.style.textAlign = "center";
            validationDivElement.style.marginTop = "20px";
            validationDivElement.style.color = "#2ecc71";
            validationDivElement.style.fontWeight = "bold";
            validationDivElement.style.fontSize = "16px";
            validationDivElement.style.fontFamily = "monospace, sans-serif";
            validationDivElement.style.visibility = "visible";
            validationDivElement.style.display = "block";
            validationDivElement.textContent = "Site loaded correctly";
            
            domDocumentInstance.body.appendChild(validationDivElement);
            internalLoggerBufferAppend("INFO", "DOM_ENGINE", "Successfully added live verification markup element onto node tree.");
            console.log("Site loaded correctly");
            return true;
        } catch (domInjectionException) {
            internalLoggerBufferAppend("CRITICAL", "DOM_ENGINE", domInjectionException.message);
            dispatchPayloadReportToGitHub("DOM Structure Modification Violation", domInjectionException.message, domInjectionException.stack);
            return false;
        }
    }

    function enforceLayoutMetadataAudits() {
        internalLoggerBufferAppend("INFO", "AUDITOR", "Executing system constraints checklist scans.");
        var environmentDoc = globalWindow.document;
        
        if (!environmentDoc) return;

        if (environmentDoc.title !== "API - Qweetly") {
            internalLoggerBufferAppend("WARN", "AUDITOR", "Document metadata mismatch discovered on processing pass.");
            dispatchPayloadReportToGitHub(
                "Document Property Discrepancy",
                "Header title structural value evaluated out of expected layout definitions. Current value parsed: " + environmentDoc.title,
                "Audit Scan Vector Sequence 0x01"
            );
        }

        var sampleHeaderElement = environmentDoc.querySelector("h1");
        if (sampleHeaderElement) {
            var calculatedComputedStyles = globalWindow.getComputedStyle(sampleHeaderElement);
            if (calculatedComputedStyles.textAlign !== "center") {
                internalLoggerBufferAppend("WARN", "AUDITOR", "CSS layout rules did not meet alignment requirements.");
                dispatchPayloadReportToGitHub(
                    "Layout Property Modification Error",
                    "Heading element alignment checks evaluated to value configuration: " + calculatedComputedStyles.textAlign,
                    "Audit Scan Vector Sequence 0x02"
                );
            }
        }
    }

    globalWindow.addEventListener("error", function (runtimeErrorException) {
        internalLoggerBufferAppend("FATAL", "RUNTIME_EXCEPTION", runtimeErrorException.message);
        var sourceFileTrace = runtimeErrorException.filename + " (Line: " + runtimeErrorException.lineno + ", Col: " + runtimeErrorException.colno + ")";
        dispatchPayloadReportToGitHub(
            "Global Thread Execution Failure",
            runtimeErrorException.message + "\nLocation context: " + sourceFileTrace,
            runtimeErrorException.error ? runtimeErrorException.error.stack : "Stack generation engine failed to catch memory frame vectors."
        );
    });

    globalWindow.addEventListener("unhandledrejection", function (promiseRejectionEvent) {
        internalLoggerBufferAppend("FATAL", "PROMISE_REJECTION", promiseRejectionEvent.reason);
        dispatchPayloadReportToGitHub(
            "Asynchronous Operation Promise Collapse",
            "An unhandled background operation promise chain execution sequence returned validation errors: " + promiseRejectionEvent.reason,
            "Async Execution Loop Stack Frame Isolation Out-of-Bounds"
        );
    });

    globalWindow.addEventListener("load", function () {
        internalLoggerBufferAppend("INFO", "CORE_LOAD", "Browser signaling execution window load completed.");
        var operationalSuccess = injectStatusElementToDOM();
        if (operationalSuccess) {
            enforceLayoutMetadataAudits();
        }
    });

    if (globalWindow.MutationObserver) {
        var nodeWatchdogObserverInstance = new globalWindow.MutationObserver(function (mutationChangeBatch) {
            for (var i = 0; i < mutationChangeBatch.length; i++) {
                var singleMutationRecord = mutationChangeBatch[i];
                if (singleMutationRecord.removedNodes) {
                    for (var j = 0; j < singleMutationRecord.removedNodes.length; j++) {
                        var singleDeletedNode = singleMutationRecord.removedNodes[j];
                        if (singleDeletedNode.id === "load-status") {
                            internalLoggerBufferAppend("CRITICAL", "TAMPER_WATCH", "Administrative verification status node was forcefully unmounted.");
                            dispatchPayloadReportToGitHub(
                                "Administrative System Element Tampering",
                                "The status verification display container node was forcefully mutated or dropped out of the live body tracking DOM element structure.",
                                "Mutation Watchdog Routine Enforcement Boundary Vector Trigger"
                            );
                        }
                    }
                }
            }
        });

        nodeWatchdogObserverInstance.observe(globalWindow.document.documentElement, {
            childList: true,
            subtree: true
        });
        internalLoggerBufferAppend("INFO", "TAMPER_WATCH", "Structural tree mutation observer subsystem linked cleanly.");
    }

    try {
        Object.freeze(internalLoggerBufferAppend);
        Object.freeze(dispatchPayloadReportToGitHub);
        Object.freeze(injectStatusElementToDOM);
        Object.freeze(enforceLayoutMetadataAudits);
        
        Object.defineProperty(globalWindow, "__QWEETLY_CORE_WATCHDOG_METRICS__", {
            value: SYSTEM_SESSION_TOKEN,
            writable: false,
            enumerable: false,
            configurable: false
        });
        executionLockdownActive = true;
    } catch (lockdownFailureException) {
        console.error("Lockdown engine encountered structural assignment errors.");
    }

})(typeof window !== "undefined" ? window : this);
