Java.perform(function () {

    function detectPII(key, value) {

        var pii_type = "none";

        if (!value) return pii_type;

        value = value.toString();

        if (/password|pass|pwd/i.test(key))
            pii_type = "password";

        else if (/token|session|auth/i.test(key))
            pii_type = "token";

        else if (/secret|apikey/i.test(key))
            pii_type = "secret";

        else if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))
            pii_type = "email";

        else if (/^\+?[0-9]{10,15}$/.test(value))
            pii_type = "phone";

        else if (/^[0-9a-f]{16}$/i.test(value))
            pii_type = "device_id";

        return pii_type;
    }


    console.log(JSON.stringify({
        event: "monitor_start",
        module: "runtime_storage_monitor"
    }));


    /* =========================
       SharedPreferences Monitor
       ========================= */

    try {

        var EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

        EditorImpl.putString.overload('java.lang.String', 'java.lang.String')
        .implementation = function (key, value) {

            var pii = detectPII(key, value);

            var Log = Java.use("android.util.Log");
            var Exception = Java.use("java.lang.Exception");
            var stack = Log.getStackTraceString(Exception.$new());

            var event = {
                event: "storage_write",
                storage_type: "SharedPreferences",
                key: key,
                value: value,
                pii_type: pii,
                sensitive: pii !== "none",
                stacktrace: stack
            };

            console.log(JSON.stringify(event));

            return this.putString(key, value);
        };

        console.log(JSON.stringify({
            event: "hook_installed",
            target: "SharedPreferences"
        }));

    } catch (e) {

        console.log(JSON.stringify({
            event: "hook_failed",
            target: "SharedPreferences",
            error: e.toString()
        }));
    }


    /* =========================
       SQLite Monitor
       ========================= */

    try {

        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

        SQLiteDatabase.insert.overload(
            'java.lang.String',
            'java.lang.String',
            'android.content.ContentValues'
        ).implementation = function (table, nullColumnHack, values) {

            var event = {
                event: "sqlite_insert",
                storage_type: "SQLite",
                table: table,
                values: values.toString()
            };

            console.log(JSON.stringify(event));

            return this.insert(table, nullColumnHack, values);
        };

        console.log(JSON.stringify({
            event: "hook_installed",
            target: "SQLiteDatabase"
        }));

    } catch (e) {

        console.log(JSON.stringify({
            event: "hook_failed",
            target: "SQLiteDatabase",
            error: e.toString()
        }));
    }

});
