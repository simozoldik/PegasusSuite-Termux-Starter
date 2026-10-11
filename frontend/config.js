/* Pegasus Suite — runtime configuration.
 * No backend URL is hard-coded because the previous Windows PC/LAN endpoint
 * is not guaranteed to exist. Set PEGASUS_API_BASE_URL in GitHub Actions
 * repository variables, or configure the backend URL in the app settings.
 */
window.__PEGASUS_CONFIG__ = {
  apiBaseUrl: "",
  environment: "unconfigured",
};
