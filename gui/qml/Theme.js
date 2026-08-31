.pragma library

// ---------------------------------------------------------------- colors ----
var bg_base        = "#07080E";   // near-black base
var bg_surface     = "#0D1220";   // dark blue cards/panels
var bg_elevated    = "#151B2C";   // hover states, elevated surfaces
var bg_input       = "#0F1522";   // input field backgrounds
var border         = "#1C2540";   // subtle blue border
var border_focus   = "#4B8BF5";   // focused elements

var text_primary   = "#E2E5EB";   // cool near-white
var text_secondary = "#7B8299";   // muted blue-grey
var text_disabled  = "#434B64";   // disabled state

var accent         = "#4B8BF5";   // clean blue
var accent_hover   = "#6BA0F8";   // lighter blue hover
var accent_press   = "#3972D8";   // darker blue pressed
var accent_text    = "#FFFFFF";   // white on blue

var success        = "#4ADE80";
var error          = "#EF4444";
var warning        = "#F59E0B";
var info           = "#60A5FA";

// ------------------------------------------------------------ typography ----
var fontUi = "Segoe UI";
var fontMono = "Cascadia Mono";

var title    = 22;
var subtitle = 12;
var body     = 13;
var caption  = 11;
var mono     = 12;

// --------------------------------------------------------------- helpers ----
function statusColor(status) {
    switch (status) {
    case "packing": return warning;
    case "done":    return success;
    case "error":   return error;
    case "ready":   return text_secondary;
    default:        return text_secondary;
    }
}
