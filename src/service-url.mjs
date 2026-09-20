// The VaultBytes Verify service URL that the Action uses when neither the `api-url` input nor a VBV_API_URL
// environment variable is set (SPEC v0.3: only `token` is required). infra/set-action-url.sh rewrites this line at
// deploy time; until then it is a placeholder under the reserved .invalid domain, and the Action refuses to run.
export const DEFAULT_API_URL = "https://ca-vbv-api.salmonsea-15cba38c.uksouth.azurecontainerapps.io";
