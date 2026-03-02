Java.perform(function () {

    console.log("=== Runtime Storage Monitoring Started ===");

    // SharedPreferences Monitoring
    try {
        var EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

        EditorImpl.putString.overload('java.lang.String', 'java.lang.String')
            .implementation = function (key, value) {

                console.log("\n[SharedPreferences WRITE]");
                console.log("Key:", key);
                console.log("Value:", value);

                // Basic sensitive detection
                if (key.toLowerCase().includes("pass") ||
                    key.toLowerCase().includes("token") ||
                    key.toLowerCase().includes("secret")) {

                    console.log("[⚠️ SENSITIVE DATA DETECTED]");
                }

                // Print stack trace for audit
                var Log = Java.use("android.util.Log");
                var Exception = Java.use("java.lang.Exception");
                console.log(Log.getStackTraceString(Exception.$new()));

                return this.putString(key, value);
            };

        console.log("SharedPreferences hook installed");

    } catch (e) {
        console.log("SharedPreferences hook failed:", e);
    }

    // SQLite Monitoring
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

        SQLiteDatabase.insert.overload(
            'java.lang.String',
            'java.lang.String',
            'android.content.ContentValues'
        ).implementation = function (table, nullColumnHack, values) {

            console.log("\n[SQLite INSERT]");
            console.log("Table:", table);
            console.log("Values:", values);

            return this.insert(table, nullColumnHack, values);
        };

        console.log("SQLite hook installed");

    } catch (e) {
        console.log("SQLite hook failed:", e);
    }

});
