Java.perform(function () {

    var StringClass = Java.use("java.lang.String");
    var originalEquals = StringClass.equals.overload('java.lang.Object');

    StringClass.equals.overload('java.lang.Object').implementation = function (obj) {

        var result = originalEquals.call(this, obj);

        console.log("[COMPARE]", this.toString(), "vs", obj, "=>", result);

        return result;
    };

});
