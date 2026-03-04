# DIVA Runtime Security Analysis using Frida

## Overview

This project demonstrates **dynamic runtime instrumentation of Android applications using Frida** to analyze insecure data handling and authentication mechanisms.

The objective is to simulate a **runtime security audit system** capable of:

* Detecting sensitive data written to local storage
* Identifying hardcoded secrets in application logic
* Demonstrating authentication bypass
* Monitoring runtime behavior of Android applications
* Generating structured JSON logs for security analysis

Target Application:

**DIVA – Damn Insecure and Vulnerable App**

Testing Approach:

Dynamic Application Security Testing (**DAST**) using runtime instrumentation.

---

# Environment Setup

* Android Emulator (Pixel device)
* Android API Level: 33
* CPU Architecture: arm64-v8a
* Emulator Type: `userdebug` (root-enabled)
* Frida Version: 17.6.2
* Frida Server deployed at:

```
/data/local/tmp/frida-server
```

Host System:

macOS (Apple Silicon)

---

# Methodology

## 1. Attach Frida to Running Application

```
frida -U -n Diva
```

This attaches the Frida instrumentation engine to the running process.

---

# 2. Enumerate Loaded Classes

Using Frida, loaded classes inside the application were enumerated to identify security-sensitive components.

Example:

```
jakhar.aseem.diva.HardcodeActivity
jakhar.aseem.diva.InsecureDataStorage1Activity
jakhar.aseem.diva.SQLInjectionActivity
```

---

# 3. Hardcoded Secret Discovery

The application performs password validation using a **hardcoded secret**.

A hook was implemented on `java.lang.String.equals()` to intercept password comparisons.

Example hook:

```
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

Observed runtime output:

```
[COMPARE] 1234 vs vendorsecretkey => false
```

This revealed the **hardcoded credential** embedded inside the application.

---

# 4. Authentication Bypass

Client-side authentication logic was bypassed by overriding the validation method.

```
Java.perform(function () {

    var Hardcode = Java.use("jakhar.aseem.diva.HardcodeActivity");

    Hardcode.access.implementation = function (view) {

        console.log("Bypassing authentication...");
        this.access(view);

    };

});
```

Result:

* Authentication succeeded regardless of password input.
* Demonstrates the risk of **client-side security validation**.

---

# 5. Runtime Storage Monitoring

A runtime monitoring module was implemented to intercept **data written to local storage**.

Monitored APIs:

* `SharedPreferences.putString()`
* `SQLiteDatabase.insert()`

Example event:

```
{
 "event":"storage_write",
 "storage_type":"SharedPreferences",
 "key":"password",
 "value":"sky123",
 "pii_type":"password",
 "sensitive":true
}
```

This confirms that sensitive data was written to insecure storage.

---

# 6. PII Detection Engine

The monitoring module automatically detects common PII patterns such as:

* Passwords
* Authentication tokens
* API keys
* Email addresses
* Phone numbers
* Device identifiers

Example detection:

```
{
 "event":"storage_write",
 "key":"user",
 "value":"thanish@gmail.com",
 "pii_type":"email",
 "sensitive":true
}
```

---

# 7. Runtime Stack Trace Capture

Each storage event includes the **exact execution path** responsible for writing the data.

Example:

```
jakhar.aseem.diva.InsecureDataStorage1Activity.saveCredentials()
```

This enables developers to locate insecure code paths quickly.

---

# Example Runtime Output

```
{
 "event":"storage_write",
 "storage_type":"SharedPreferences",
 "key":"password",
 "value":"sky123",
 "pii_type":"password",
 "sensitive":true
}
```

```
{
 "event":"storage_write",
 "storage_type":"SharedPreferences",
 "key":"user",
 "value":"thanish@gmail.com",
 "pii_type":"email",
 "sensitive":true
}
```

---

# Repository Structure

```
diva-runtime-analysis
│
├── hooks
│   ├── list_classes.js
│   ├── equals_logger.js
│   ├── hardcode_bypass.js
│   └── runtime_storage_monitoring.js
│
├── dataset
│   └── storage_logs.json
│
└── README.md
```

---

# How to Run

### Start Frida Server

```
adb shell
su
/data/local/tmp/frida-server
```

---

### Attach Monitoring Script

```
frida -U -n Diva -l hooks/runtime_storage_monitoring.js
```

---

### Collect JSON Dataset

```
frida -U -n Diva -l hooks/runtime_storage_monitoring.js -q > storage_logs.json
```

---

# Key Findings

| Vulnerability              | Severity | Impact                            |
| -------------------------- | -------- | --------------------------------- |
| Hardcoded Secret           | High     | Credential extraction             |
| Client-side Authentication | Critical | Full authentication bypass        |
| Insecure Local Storage     | High     | Sensitive data leakage            |
| Lack of Runtime Protection | High     | Application behavior manipulation |

---

# Security Impact

An attacker with runtime instrumentation capabilities can:

* Extract embedded secrets
* Intercept sensitive data flows
* Modify application behavior
* Bypass authentication controls

This demonstrates why **client-side security enforcement alone is insufficient**.

---

# Mitigation Recommendations

* Remove hardcoded credentials
* Move authentication logic to server-side
* Implement code obfuscation
* Add runtime integrity checks
* Implement root/tamper detection
* Use Play Integrity API for validation

---

# Disclaimer

This research was conducted in a controlled environment using a deliberately vulnerable application (**DIVA**) for educational and security research purposes only.
