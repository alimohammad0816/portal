export type AuthKind = "certificate" | "user_pass" | "user_pass_challenge";

export interface Profile {
  id: string;
  name: string;
  group: string;
  country: string | null;
  remote_host: string;
  remote_port: number;
  proto: string;
  auth: AuthKind;
  challenge: string | null;
  source_file: string;
  imported_at: number;
  last_connected_at: number | null;
}

export type ConnState = "disconnected" | "connecting" | "needs_credentials" | "connected" | "disconnecting";

export interface Status {
  state: ConnState;
  profile_id: string | null;
  detail: string | null;
  connected_since: number | null;
  tunnel_ip: string | null;
  server_ip: string | null;
  bytes_in: number;
  bytes_out: number;
  rate_in: number;
  rate_out: number;
  error: string | null;
  firewall_active: boolean;
  internet_blocked: boolean;
  dns_servers: string[];
  split_active: boolean;
  split_needs_reconnect: boolean;
  split_processes: number;
  proxy_address: string | null;
}

export type SplitMode = "exclude" | "include";

export interface SplitApp {
  name: string;
  path: string;
}

export interface SplitSettings {
  enabled: boolean;
  mode: SplitMode;
  apps: SplitApp[];
  hosts: string[];
  countries: string[];
}

export interface InstalledApp {
  name: string;
  path: string;
  icon: string | null;
}

export type FirewallMode = "off" | "auto" | "always";

export type DnsMode = { mode: "vpn" } | { mode: "custom"; servers: string[] };

export interface Settings {
  firewall: FirewallMode;
  allow_lan: boolean;
  block_ipv6: boolean;
  dns: DnsMode;
  dns_leak_protection: boolean;
  split: SplitSettings;
  proxy_gateway: { enabled: boolean; port: number };
}

export const defaultSettings: Settings = {
  firewall: "auto",
  allow_lan: true,
  block_ipv6: true,
  dns: { mode: "vpn" },
  dns_leak_protection: true,
  split: { enabled: false, mode: "exclude", apps: [], hosts: [], countries: [] },
  proxy_gateway: { enabled: false, port: 1080 },
};

export interface ImportResult {
  imported: Profile[];
  errors: { file: string; message: string }[];
}

export interface DaemonInfo {
  bus: "system" | "session";
  reachable: boolean;
  error: string | null;
}

export interface Release {
  version: string;
  notes: string;
  url: string;
  published_at: string;
}

export interface UpdateInfo {
  current: string;
  enabled: boolean;
  available: Release | null;
}

export interface Versions {
  app: string;
  daemon: string | null;
}

export const emptyStatus: Status = {
  state: "disconnected",
  profile_id: null,
  detail: null,
  connected_since: null,
  tunnel_ip: null,
  server_ip: null,
  bytes_in: 0,
  bytes_out: 0,
  rate_in: 0,
  rate_out: 0,
  error: null,
  firewall_active: false,
  internet_blocked: false,
  dns_servers: [],
  split_active: false,
  split_needs_reconnect: false,
  split_processes: 0,
  proxy_address: null,
};

export interface Prefs {
  launch_at_login: boolean;
  connect_on_launch: boolean;
  auto_connect_untrusted: boolean;
  trusted_networks: string[];
  auto_profile: string | null;
  show_exit_location: boolean;
}

export const defaultPrefs: Prefs = {
  launch_at_login: false,
  connect_on_launch: false,
  auto_connect_untrusted: false,
  trusted_networks: [],
  auto_profile: null,
  show_exit_location: true,
};

export interface Network {
  name: string;
  wireless: boolean;
}

export interface ExitInfo {
  ip: string;
  country_code: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
}

