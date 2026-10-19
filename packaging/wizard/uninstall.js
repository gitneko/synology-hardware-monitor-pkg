/* DSM 7.2.2+ JSONP module, matching Synology's ExamplePackages wizard entry.
 * Uses DSM's Vue 2 runtime; no monitoring UI or external dependencies are loaded.
 */
(function () {
  "use strict";
  var text = __WIZARD_TEXT__;
  var hook = SYNO.SDS.PkgManApp.Custom.useHook;
  var component = {
    props: hook.props,
    setup: function (props) {
      var api = hook(props);
      var removeData = Vue.ref(false);
      return {
        getNext: api.getNext,
        checkState: api.checkState,
        headline: text.title,
        removeData: removeData,
        getValues: function () {
          return { wizard_delete_data: removeData.value === true };
        }
      };
    },
    render: function (h) {
      var self = this;
      return h("pkg-center-step-content", [
        h("v-form", { attrs: { "syno-id": "uninstall-form" } }, [
          h("v-form-item", {
            props: { hideLabel: true, textonly: true },
            attrs: { "syno-id": "uninstall-description" }
          }, [text.description]),
          h("v-form-item", {
            props: { hideLabel: true },
            attrs: { "syno-id": "uninstall-option" }
          }, [h("v-checkbox", {
            attrs: { "syno-id": "delete-data" },
            model: {
              value: self.removeData,
              callback: function (value) { self.removeData = value === true; }
            }
          }, [text.checkbox])])
        ])
      ]);
    }
  };
  var exports = { default: { name: "hardware_monitor_uninstall", render: component } };
  Object.defineProperty(exports, "__esModule", { value: true });
  SYNO.SDS.PkgManApp.Custom.JsonpLoader.load(exports);
}());
