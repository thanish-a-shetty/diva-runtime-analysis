DIVA Runtime Security Analysis using Frida
Overview

This project demonstrates dynamic runtime instrumentation of an Android application using Frida.

The objective was to analyze client-side authentication logic and extend the analysis to validate runtime storage behavior.

The project demonstrates:

Hardcoded secret extraction

Authentication bypass

Runtime method interception

Runtime storage monitoring

Sensitive data detection

Target Application: DIVA (Damn Insecure and Vulnerable App)
Testing Type: Dynamic Application Security Testing (DAST)

Environment Setup

Android Emulator (API 33, arm64-v8a)

userdebug build (root-enabled)

Frida 17.6.2

frida-server deployed to /data/local/tmp

Phase 1 – Authentication Analysis
1. Attached to Running Process
frida -U -n Diva
2. Enumerated Loaded Classes

Identified target activity:

jakhar.aseem.diva.HardcodeActivity
3. Hooked String.equals() to Intercept Password Comparisons
Java.perform(function () {

    var StringClass = Java.use("java.lang.String");
    var originalEquals = StringClass.equals.overload('java.lang.Object');

    StringClass.equals.overload('java.lang.Object').implementation = function (obj) {

        var result = originalEquals.call(this, obj);

        console.log("[COMPARE]", this.toString(), "vs", obj, "=>", result);

        return result;
    };

});
4. Hardcoded Secret Identified at Runtime

During authentication attempt:

[COMPARE] 1234 vs vendorsecretkey => false

Extracted hardcoded credential:

vendorsecretkey
5. Authentication Bypass via Method Override
Java.perform(function () {

    var Hardcode = Java.use("jakhar.aseem.diva.HardcodeActivity");

    Hardcode.access.implementation = function (view) {

        console.log("Bypassing authentication...");
        this.access(view);
    };

});
Result

Access granted regardless of password input

Client-side validation fully bypassed

Phase 2 – Runtime Storage Validation

The analysis was extended to validate whether sensitive data is persisted during execution.

Objective

Validate if credentials predicted during static inspection are actually written to device storage at runtime.

Hooked APIs

android.app.SharedPreferencesImpl$EditorImpl.putString

android.database.sqlite.SQLiteDatabase.insert

Runtime Storage Monitoring Script
Java.perform(function () {

    console.log("=== Runtime Storage Monitoring Started ===");

    var EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

    EditorImpl.putString.overload('java.lang.String', 'java.lang.String')
        .implementation = function (key, value) {

            console.log("\n[SharedPreferences WRITE]");
            console.log("Key:", key);
            console.log("Value:", value);

            if (key.toLowerCase().includes("pass") ||
                key.toLowerCase().includes("token") ||
                key.toLowerCase().includes("secret")) {

                console.log("[⚠️ SENSITIVE DATA DETECTED]");
            }

            return this.putString(key, value);
        };

});
Example Runtime Output
[SharedPreferences WRITE]
Key: user
Value: than

[SharedPreferences WRITE]
Key: password
Value: sigma
[⚠️ SENSITIVE DATA DETECTED]
Key Findings
Vulnerability	Severity	Impact
Hardcoded Secret	High	Credential extraction
Client-side Authentication	Critical	Full bypass possible
Plaintext Credential Storage	High	Local data exposure
Lack of Runtime Protection	High	Execution flow modification
Security Impact

An attacker can:

Extract embedded secrets

Modify validation logic at runtime

Bypass authentication controls

Confirm sensitive credential persistence

Identify insecure storage mechanisms

This demonstrates why:

Client-side authentication is insecure

Secrets must not be hardcoded

Sensitive data must not be stored in plaintext

Runtime validation is essential for security auditing

Mitigation Recommendations

Remove hardcoded secrets

Move authentication logic to server-side

Encrypt sensitive data before storage

Implement secure key management (Android Keystore)

Add root/tamper detection

Use runtime integrity verification (Play Integrity API)

How To Run
Start frida-server
adb shell
su
/data/local/tmp/frida-server
Attach and Load Script
frida -U -n Diva -l hooks/runtime_storage_monitor.js
Repository Structure
hooks/
  ├── list_classes.js
  ├── equals_logger.js
  ├── hardcode_bypass.js
  └── runtime_storage_monitor.js
Conclusion

This project demonstrates a structured progression:

Runtime extraction of embedded secrets

Authentication bypass via dynamic instrumentation

Runtime validation of sensitive data persistence

Confirmation of insecure storage practices

It highlights the importance of dynamic analysis in validating real-world exploitability beyond theoretical vulnerabilities.

Disclaimer

This project was performed in a controlled lab environment on a deliberately vulnerable application for educational purposes only.
