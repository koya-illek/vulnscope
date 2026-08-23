// Same-origin API base. The site serves both the page and the API from
// https://scan.illek.ie, and local `wrangler dev` sessions serve them from one
// localhost origin too, so a relative base is correct everywhere. An absolute
// URL here would turn every call cross-origin (CORS 403) whenever the page is
// served from any other origin, including local development.
window.VULN_SCANNER_CONFIG = {
  API_BASE: ""
};
