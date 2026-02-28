Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            if (name.includes("diva")) {
                console.log(name);
            }
        },
        onComplete: function() {
            console.log("Done.");
        }
    });
});
