# DIVA Runtime Security Analysis using Frida

## Overview

This project demonstrates dynamic runtime instrumentation of an Android application using **Frida**.  
The objective was to analyze client-side authentication logic and demonstrate:

- Hardcoded secret extraction
- Authentication bypass
- Runtime method interception

Target Application: **DIVA (Damn Insecure and Vulnerable App)**  
Testing Type: Dynamic Application Security Testing (DAST)

---

## Environment Setup

- Android Emulator (API 33, arm64-v8a)
- userdebug build (root-enabled)
- Frida 17.6.2
- frida-server deployed to `/data/local/tmp`

---

## Methodology

### 1. Attached to Running Process

```bash
frida -U -n Diva
```

---

### 2. Enumerated Loaded Classes

Identified target activity:

```
jakhar.aseem.diva.HardcodeActivity
```

---

### 3. Hooked `String.equals()` to Intercept Password Comparisons

```javascript
Java.perform(function () {

    var StringClass = Java.use("java.lang.String");
    var originalEquals = StringClass.equals.overload('java.lang.Object');

    StringClass.equals.overload('java.lang.Object').implementation = function (obj) {

        var result = originalEquals.call(this, obj);

        console.log("[COMPARE]", this.toString(), "vs", obj, "=>", result);

        return result;
    };

});
```

---

### 4. Hardcoded Secret Identified at Runtime

During authentication attempt:

```
[COMPARE] 1234 vs vendorsecretkey => false
```

Extracted hardcoded credential:

```
vendorsecretkey
```

---

### 5. Authentication Bypass via Method Override

```javascript
Java.perform(function () {

    var Hardcode = Java.use("jakhar.aseem.diva.HardcodeActivity");

    Hardcode.access.implementation = function (view) {

        console.log("Bypassing authentication...");
        this.access(view); // optional: remove to fully skip validation
    };

});
```

Result:
- Access granted regardless of password input
- Client-side validation fully bypassed

---

## Key Findings

| Vulnerability | Severity | Impact |
|---------------|----------|--------|
| Hardcoded Secret | High | Credential extraction |
| Client-side Authentication | Critical | Full bypass possible |
| Lack of Runtime Protection | High | Execution flow modification |

---

## Security Impact

An attacker can:

- Extract embedded secrets
- Modify validation logic at runtime
- Bypass authentication controls
- Intercept sensitive method calls

This demonstrates why client-side security validation alone is insufficient.

---

## Mitigation Recommendations

- Remove hardcoded secrets
- Move authentication logic to server-side
- Implement code obfuscation
- Add root/tamper detection
- Use runtime integrity verification (Play Integrity API)

---

## How To Run

### Start frida-server

```bash
adb shell
su
/data/local/tmp/frida-server
```

### Attach and Load Script

```bash
frida -U -n Diva -l hooks/equals_logger.js
```

---

## Repository Structure

```
hooks/
  ├── list_classes.js
  ├── equals_logger.js
  └── hardcode_bypass.js
```

---

## Disclaimer

This project was performed in a controlled lab environment on a deliberately vulnerable application for educational purposes only.
