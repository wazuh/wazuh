// VD Context Evaluator Logic Example
// This shows the decision flow we should implement

#include <vector>
#include <string>

struct VDEvent {
    std::string table;     // "packages", "os_info", "hotfixes"
    std::string operation; // "INSERTED", "MODIFIED", "DELETED"
    bool is_data_context;
    std::string data;
};

class VDContextEvaluator {
public:
    bool shouldGenerateContext(const std::vector<VDEvent>& events) {
        // Step 1: Analyze what types of events we have
        bool hasOSChange = false;
        bool hasPackageChanges = false;
        bool hasHotfixChanges = false;
        std::string detectedOS = detectOperatingSystem();

        for (const auto& event : events) {
            if (event.table == "os_info") {
                hasOSChange = true;
            }
            else if (event.table == "packages") {
                hasPackageChanges = true;
            }
            else if (event.table == "hotfixes") {
                hasHotfixChanges = true;
            }
        }

        // Step 2: Decision logic based on event types
        if (hasOSChange) {
            // OS change ALWAYS requires context (regardless of OS)
            logInfo("OS change detected - context required");
            return true;
        }

        if (hasHotfixChanges) {
            // Hotfixes ALWAYS require context (Windows-specific but safe)
            logInfo("Hotfix changes detected - context required");
            return true;
        }

        if (hasPackageChanges) {
            if (detectedOS == "Linux") {
                // Linux package changes - NO context needed
                logInfo("Linux package changes detected - no context needed");
                return false;
            }
            else if (detectedOS == "Windows") {
                // Windows package changes - maybe need context?
                logInfo("Windows package changes detected - context required");
                return true;
            }
        }

        // No relevant changes
        logInfo("No changes requiring context");
        return false;
    }

private:
    std::string detectOperatingSystem() {
        // TODO: Implement OS detection from events or system
        return "Linux"; // placeholder
    }

    void logInfo(const std::string& message) {
        // Placeholder for logging
    }
};

// Example usage showing the decision flow:
void exampleScenarios() {
    VDContextEvaluator evaluator;
    
    // Scenario 1: Your example - "1 OS change, 10 package changes on Linux"
    std::vector<VDEvent> scenario1 = {
        {"os_info", "MODIFIED", false, "{}"},      // OS change
        {"packages", "INSERTED", false, "{}"},     // Package 1
        {"packages", "MODIFIED", false, "{}"},     // Package 2
        // ... 8 more package changes
    };
    bool needsContext1 = evaluator.shouldGenerateContext(scenario1);
    // Result: TRUE (because OS change overrides package logic)
    
    // Scenario 2: "Only 10 package changes on Linux"
    std::vector<VDEvent> scenario2 = {
        {"packages", "INSERTED", false, "{}"},     // Package 1
        {"packages", "MODIFIED", false, "{}"},     // Package 2
        // ... 8 more package changes
    };
    bool needsContext2 = evaluator.shouldGenerateContext(scenario2);
    // Result: FALSE (Linux packages don't need context)
    
    // Scenario 3: "Hotfix changes on Windows"
    std::vector<VDEvent> scenario3 = {
        {"hotfixes", "INSERTED", false, "{}"},     // Hotfix 1
        {"hotfixes", "MODIFIED", false, "{}"},     // Hotfix 2
    };
    bool needsContext3 = evaluator.shouldGenerateContext(scenario3);
    // Result: TRUE (hotfixes always need context)
}