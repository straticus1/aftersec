import Cocoa
import Foundation

// MARK: - Application Subclass
@objc(AfterSecApplication)
class AfterSecApplication: NSApplication {
    // The property 'security score' maps to 'securityScore' via Cocoa key
    @objc var securityScore: Int {
        // Attempt to call the CLI to get the score.
        // We parse the output to an integer. If it fails, return 100 as placeholder.
        let output = runGoCLI(args: ["status", "--score-only"]) ?? "100"
        return Int(output) ?? 100
    }
}

// MARK: - Commands
@objc(ScanCommand)
class ScanCommand: NSScriptCommand {
    override func performDefaultImplementation() -> Any? {
        // folderPath comes from the 'folder' parameter
        let folderArgs = self.evaluatedArguments
        let targetFolder = folderArgs?["folderPath"] as? String ?? "/"
        
        // Convert the result to a string so AppleScript can read it
        return runGoCLI(args: ["scan", "--path", targetFolder]) ?? "Scan failed"
    }
}

@objc(RemediateCommand)
class RemediateCommand: NSScriptCommand {
    override func performDefaultImplementation() -> Any? {
        // The direct parameter is the finding name
        guard let findingName = self.directParameter as? String else {
            return "Error: No finding name provided."
        }
        
        return runGoCLI(args: ["remediate", findingName]) ?? "Remediation failed"
    }
}

// MARK: - Go CLI Integration
func runGoCLI(args: [String]) -> String? {
    // The core Go binary will be packaged alongside the Swift binary in MacOS/
    let bundlePath = Bundle.main.bundlePath
    let executablePath = bundlePath + "/Contents/MacOS/aftersec"
    
    let fm = FileManager.default
    if !fm.fileExists(atPath: executablePath) {
        return "Error: Go binary 'aftersec' not found at \(executablePath)"
    }

    let task = Process()
    task.executableURL = URL(fileURLWithPath: executablePath)
    task.arguments = args
    
    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = pipe
    
    do {
        try task.run()
        task.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        if let output = String(data: data, encoding: .utf8) {
            return output.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    } catch {
        return "Error executing AfterSec core: \(error)"
    }
    return nil
}

// MARK: - App Delegate & Main
class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Ready to receive AppleEvents
    }
}

// Bootstrap the application
let app = AfterSecApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
_ = NSApplicationMain(CommandLine.argc, CommandLine.unsafeArgv)
