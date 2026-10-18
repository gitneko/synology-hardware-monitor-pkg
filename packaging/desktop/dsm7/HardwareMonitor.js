/* DSM host shell follows SynologyOpenSource/ExamplePackages (Vue 2).
 * The Vue 3 monitoring UI stays isolated inside a same-origin iframe.
 * No window.open, external origin, password or session token is used here.
 */
(function () {
  "use strict";
  SYNO.namespace("SYNO.SDS.App.HardwareMonitor");
  SYNO.SDS.App.HardwareMonitor.Instance = Vue.extend({
    render: function (h) {
      return h("v-app-instance", {
        props: { className: "SYNO.SDS.App.HardwareMonitor.Instance" },
        attrs: { "syno-id": "HardwareMonitor.Instance" }
      }, [h("v-app-window", {
        props: { width: 1180, height: 780, resizable: true },
        attrs: { "syno-id": "HardwareMonitor.Window" }
      }, [h("iframe", {
        attrs: {
          src: "/webman/3rdparty/HardwareMonitor/index.html",
          title: "Hardware Monitor",
          referrerpolicy: "same-origin"
        },
        style: { display: "block", border: "0", width: "100%", height: "100%" }
      })])]);
    }
  });
}());
