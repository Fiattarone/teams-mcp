#!/usr/bin/env node

import { exec } from "node:child_process";
import { promises as fs } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { platform } from "node:process";
import {
  type AuthenticationResult,
  type Configuration,
  PublicClientApplication,
} from "@azure/msal-node";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { cachePlugin } from "./msal-cache.js";
import { FULL_SCOPES, GraphService, READ_ONLY_SCOPES } from "./services/graph.js";
import { registerAuthTools } from "./tools/auth.js";
import { registerChatTools } from "./tools/chats.js";
import { registerSearchTools } from "./tools/search.js";
import { registerTeamsTools } from "./tools/teams.js";
import { registerUsersTools } from "./tools/users.js";

// Microsoft Graph CLI app ID (default public client)
const CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e";
const AUTHORITY = "https://login.microsoftonline.com/common";

/** Open a URL in the system browser. */
function openBrowser(url: string): void {
  const cmd =
    platform === "darwin" ? "open" : platform === "win32" ? "start" : "xdg-open";
  exec(`${cmd} "${url}"`);
}

const AUTH_INFO_PATH = join(homedir(), ".msgraph-mcp-auth.json");

/** Check whether CLI args contain --read-only. */
function hasReadOnlyFlag(args: string[]): boolean {
  return args.includes("--read-only");
}

/** Read the persisted auth info file (best-effort). */
async function readAuthInfo(): Promise<Record<string, unknown> | undefined> {
  try {
    const data = await fs.readFile(AUTH_INFO_PATH, "utf8");
    return JSON.parse(data) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

/** Check whether CLI args contain --device-code. */
function hasDeviceCodeFlag(args: string[]): boolean {
  return args.includes("--device-code");
}

// Authentication functions
async function authenticate(readOnly: boolean, useDeviceCode: boolean) {
  const scopes = readOnly ? READ_ONLY_SCOPES : FULL_SCOPES;
  const modeLabel = readOnly ? "read-only" : "full access";

  console.log("🔐 Microsoft Graph Authentication for MCP Server");
  console.log("=".repeat(50));
  console.log(`Using Microsoft Graph CLI app (${modeLabel})`);

  const msalConfig: Configuration = {
    auth: {
      clientId: CLIENT_ID,
      authority: AUTHORITY,
    },
    cache: {
      cachePlugin, // Use our custom file-based cache for refresh tokens
    },
  };

  const client = new PublicClientApplication(msalConfig);

  try {
    let result: AuthenticationResult | null;

    if (useDeviceCode) {
      console.log("\n📱 Using device code flow...");
      result = await client.acquireTokenByDeviceCode({
        scopes,
        deviceCodeCallback: (response) => {
          console.log("\n📱 Please complete authentication:");
          console.log(`🌐 Visit: ${response.verificationUri}`);
          console.log(`🔑 Enter code: ${response.userCode}`);
          console.log("\n⏳ Waiting for you to complete authentication...");
        },
      });
    } else {
      console.log("\n🌐 Opening browser for interactive login...");
      result = await client.acquireTokenInteractive({
        scopes,
        openBrowser: async (url) => {
          console.log(`\n🌐 If the browser doesn't open automatically, visit:\n   ${url}`);
          openBrowser(url);
        },
        successTemplate:
          "<h1>Authentication successful!</h1><p>You can close this window and return to the terminal.</p>",
        errorTemplate:
          "<h1>Authentication failed</h1><p>{{error}}</p><p>Please close this window and try again.</p>",
      });
    }

    if (result) {
      // Save authentication info (for quick status checks via CLI)
      const authInfo = {
        clientId: CLIENT_ID,
        authenticated: true,
        timestamp: new Date().toISOString(),
        expiresAt: result.expiresOn?.toISOString(),
        account: result.account?.username,
        grantedScopes: result.scopes,
      };

      await fs.writeFile(AUTH_INFO_PATH, JSON.stringify(authInfo, null, 2));

      console.log("\n✅ Authentication successful!");
      console.log(`👤 Signed in as: ${result.account?.username || "Unknown"}`);
      console.log(`🔒 Mode: ${modeLabel}`);
      console.log(`💾 Credentials saved to: ${AUTH_INFO_PATH}`);
      console.log("🔄 Refresh token cached for automatic renewal");
      console.log("\n🚀 You can now use the MCP server!");
      console.log("   The server will automatically use these credentials.");
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    // Provide helpful error messages for common issues
    if (errorMessage.includes("AADSTS50020")) {
      console.error("\n❌ Authentication failed: User account not in tenant");
    } else if (errorMessage.includes("AADSTS65001")) {
      console.error("\n❌ Authentication failed: Admin consent required");
      console.error("   Grant admin consent for the required permissions in Azure Portal");
    } else if (errorMessage.includes("AADSTS50199") || errorMessage.includes("AADSTS7000218")) {
      console.error("\n❌ Authentication failed: Device code flow is disabled for this tenant.");
      console.error("   Try interactive browser auth instead (omit --device-code).");
    } else {
      console.error("\n❌ Authentication failed:", errorMessage);
    }
    process.exit(1);
  }
}

async function checkAuth() {
  try {
    const data = await fs.readFile(AUTH_INFO_PATH, "utf8");
    const authInfo = JSON.parse(data);

    if (authInfo.authenticated && authInfo.clientId) {
      console.log("✅ Authentication found");
      console.log(`👤 Account: ${authInfo.account || "Unknown"}`);
      console.log(`📅 Authenticated on: ${authInfo.timestamp}`);

      // Show granted scope mode
      const grantedScopes = authInfo.grantedScopes as string[] | undefined;
      if (grantedScopes) {
        const hasWriteScopes = grantedScopes.some(
          (s: string) =>
            s === "ChannelMessage.Send" ||
            s === "ChannelMessage.ReadWrite" ||
            s === "Chat.ReadWrite" ||
            s === "Files.ReadWrite.All"
        );
        console.log(`🔒 Scope mode: ${hasWriteScopes ? "full access" : "read-only"}`);
      } else {
        console.log("⚠️  Scope mode: unknown (authenticated before read-only support)");
      }

      // Check if we have expiration info
      if (authInfo.expiresAt) {
        const expiresAt = new Date(authInfo.expiresAt);
        const now = new Date();

        if (expiresAt > now) {
          console.log(`⏰ Access token expires: ${expiresAt.toLocaleString()}`);
          console.log("🔄 Refresh token will automatically renew access");
          console.log("🎯 Ready to use with MCP server!");
        } else {
          console.log("⏰ Access token expired - will use refresh token");
          console.log("🎯 Ready to use with MCP server!");
        }
      } else {
        console.log("🎯 Ready to use with MCP server!");
      }
      return true;
    }
  } catch (_error) {
    console.log("❌ No authentication found");
    return false;
  }
  return false;
}

async function logout() {
  const CACHE_PATH = join(homedir(), ".teams-mcp-token-cache.json");

  try {
    await fs.unlink(AUTH_INFO_PATH);
  } catch (_error) {
    // Ignore if file doesn't exist
  }

  try {
    await fs.unlink(CACHE_PATH);
  } catch (_error) {
    // Ignore if file doesn't exist
  }

  console.log("✅ Successfully logged out");
  console.log("🔄 Run 'npx @floriscornel/teams-mcp@latest authenticate' to re-authenticate");
}

// MCP Server setup
async function startMcpServer(readOnly: boolean) {
  // Create MCP server
  const server = new McpServer({
    name: "teams-mcp",
    version: "0.8.0",
  });

  // Initialize Graph service (singleton)
  const graphService = GraphService.getInstance();
  graphService.readOnlyMode = readOnly;

  // Detect scope mismatch: warn when switching from read-only → full mode
  if (!readOnly && !process.env.AUTH_TOKEN) {
    const authInfo = await readAuthInfo();
    if (authInfo) {
      const grantedScopes = authInfo.grantedScopes as string[] | undefined;
      const hasWriteScopes = grantedScopes?.some(
        (s: string) =>
          s === "ChannelMessage.Send" ||
          s === "ChannelMessage.ReadWrite" ||
          s === "Chat.ReadWrite" ||
          s === "Files.ReadWrite.All"
      );
      if (grantedScopes && !hasWriteScopes) {
        console.error(
          "⚠️  Warning: You authenticated with read-only scopes but the server is running in full mode."
        );
        console.error("   Write operations may fail. Re-authenticate without --read-only:");
        console.error("   npx @floriscornel/teams-mcp@latest authenticate");
      } else if (!grantedScopes) {
        console.error(
          "⚠️  Warning: Could not determine granted scopes. If you experience permission errors,"
        );
        console.error("   re-authenticate: npx @floriscornel/teams-mcp@latest authenticate");
      }
    }
  }

  // Register all tools (write tools are skipped when readOnly is true)
  registerAuthTools(server, graphService, readOnly);
  registerUsersTools(server, graphService, readOnly);
  registerTeamsTools(server, graphService, readOnly);
  registerChatTools(server, graphService, readOnly);
  registerSearchTools(server, graphService, readOnly);

  // Start server
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`Microsoft Graph MCP Server started${readOnly ? " (read-only mode)" : ""}`);
}

// Main function to handle both CLI and MCP server modes
async function main() {
  const args = process.argv.slice(2);
  const command = args.find((arg) => !arg.startsWith("--"));

  const readOnly = hasReadOnlyFlag(args) || process.env.TEAMS_MCP_READ_ONLY === "true";
  const useDeviceCode = hasDeviceCodeFlag(args);

  // CLI commands
  switch (command) {
    case "authenticate":
    case "auth":
      await authenticate(readOnly, useDeviceCode);
      return;
    case "check":
      await checkAuth();
      return;
    case "logout":
      await logout();
      return;
    case "help":
    case "--help":
    case "-h":
      console.log("Microsoft Graph MCP Server");
      console.log("");
      console.log("Usage:");
      console.log(
        "  authenticate                        # Interactive browser login (full scopes)"
      );
      console.log(
        "  authenticate --read-only            # Interactive browser login (read-only)"
      );
      console.log(
        "  authenticate --device-code          # Device code flow (if browser auth blocked)"
      );
      console.log(
        "  check                               # Check authentication status"
      );
      console.log(
        "  logout                              # Clear authentication"
      );
      console.log(
        "  (no command)                        # Start MCP server"
      );
      console.log("");
      console.log("Environment variables:");
      console.log("  AZURE_TENANT_ID=<id>      # Azure AD tenant (for client credentials)");
      console.log("  AZURE_CLIENT_ID=<id>      # Azure AD app client ID");
      console.log("  AZURE_CLIENT_SECRET=<s>   # Azure AD app client secret");
      console.log("  APP_USER_ID=<id>          # User ID to act as (required for client credentials)");
      console.log("  TEAMS_MCP_READ_ONLY=true  # Start MCP server in read-only mode");
      console.log("  AUTH_TOKEN=<jwt>          # Use a pre-existing access token");
      return;
    case undefined:
      // No command = start MCP server
      await startMcpServer(readOnly);
      return;
    default:
      console.error(`Unknown command: ${command}`);
      console.error("Use --help to see available commands");
      process.exit(1);
  }
}

// Handle uncaught errors
process.on("uncaughtException", (error) => {
  console.error("Uncaught exception:", error);
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled rejection at:", promise, "reason:", reason);
  process.exit(1);
});

main().catch((error) => {
  console.error("Failed to start:", error);
  process.exit(1);
});
