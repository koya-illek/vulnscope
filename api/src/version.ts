/**
 * Single source of truth for the product version surfaced by the API
 * metadata, the MCP serverInfo, and the outbound scanner User-Agent. The
 * OpenAPI and Copilot contracts pin the same value; a release-config test
 * fails when any of them drift.
 */
export const VERSION = "2.0.0";
export const WEBSITE_ORIGIN = "https://scan.illek.ie";
