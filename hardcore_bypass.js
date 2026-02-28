Java.perform(function () {

    var Hardcode = Java.use("jakhar.aseem.diva.HardcodeActivity");

    Hardcode.access.implementation = function (view) {

        console.log("Bypassing authentication...");
        this.access(view);  // optional: remove to fully skip logic
    };

});
