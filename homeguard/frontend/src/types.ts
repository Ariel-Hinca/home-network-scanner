export type Health = {
  status: string;
  service: string;
  version: string;
  database: string;
  nmap: string;
  api_host: string;
  api_port: number;
  scope_policy: {
    address_family: string;
    allowed_ranges: string[];
    max_scope: string;
    default_scope: string;
    scan_scope: string;
  };
};

export type SetupStatus = {
  setup_completed: boolean;
  authenticated: boolean;
};

export type ValidatedCidr = {
  cidr: string;
  prefix_length: number;
  num_addresses: number;
  private: boolean;
  within_max_scope: boolean;
  host_bits_normalized: boolean;
  max_scope: string;
  default_scope: string;
};

export type InterfaceInfo = {
  name: string;
  address: string;
  netmask: string;
  interface_cidr: string;
  interface_allowed: boolean;
  suggested_scan_cidr: string | null;
  detail: string | null;
};

export type Network = {
  id: number;
  name: string;
  cidr: string;
  prefix_length: number;
  interface_name: string | null;
  ownership_confirmed: boolean;
  created_at: string;
};

export type Scan = {
  id: number;
  network_id: number;
  profile: string;
  status: string;
  error: string;
  host_count: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
};

export type DiscoveredHost = {
  ip: string;
  hostname: string;
  state: string;
  services?: { port: number; protocol: string; state: string }[];
};
