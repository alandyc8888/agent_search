// Asset and scheme allowlists. Decimals are pinned per asset; never assume 6.
// An asset that is not listed here is never converted to USD and never auto-paid.

export type Build = "dev" | "prod";

export interface AssetInfo {
  network: string; // CAIP-2
  address: string; // lowercased contract address
  symbol: string;
  decimals: number;
  usdPegged: true;
  testnet: boolean;
}

const ASSETS: AssetInfo[] = [
  // Base mainnet USDC (Circle). Source: Circle docs; matches Bazaar data.
  { network: "eip155:8453", address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", symbol: "USDC", decimals: 6, usdPegged: true, testnet: false },
  // Base Sepolia USDC (Circle testnet).
  { network: "eip155:84532", address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e", symbol: "USDC", decimals: 6, usdPegged: true, testnet: true },
];

/** Assets known for display/normalisation (both builds). */
export function lookupAsset(network: string | undefined, address: string | undefined): AssetInfo | undefined {
  if (!network || !address) return undefined;
  const a = address.toLowerCase();
  return ASSETS.find((x) => x.network === network && x.address === a);
}

/** Assets the plugin may auto-pay with. prod = mainnet only, dev = testnet only. */
export function isPayableAsset(build: Build, network: string, address: string): boolean {
  const info = lookupAsset(network, address);
  if (!info) return false;
  return build === "prod" ? !info.testnet : info.testnet;
}

/** Only schemes that are direct wallet-to-wallet transfers. auth-capture / batch-settlement hold funds in contracts. */
export const SCHEME_ALLOWLIST = new Set(["exact"]);
export const SCHEMES_HOLDING_FUNDS = new Set(["auth-capture", "batch-settlement", "escrow"]);

/** Convert an atomic amount to a decimal USD string, or null if the asset is unknown. */
export function atomicToUsd(amountAtomic: string | number | bigint, network?: string, asset?: string): string | null {
  const info = lookupAsset(network, asset);
  if (!info) return null;
  let v: bigint;
  try {
    v = BigInt(amountAtomic);
  } catch {
    return null;
  }
  if (v < 0n) return null;
  const base = 10n ** BigInt(info.decimals);
  const whole = v / base;
  const frac = (v % base).toString().padStart(info.decimals, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : `${whole}`;
}

/** Network labels for display only. */
export function networkLabel(network: string): string {
  const m: Record<string, string> = {
    "eip155:8453": "Base",
    "eip155:84532": "Base Sepolia (testnet)",
    "eip155:1": "Ethereum",
    "eip155:137": "Polygon",
    "eip155:56": "BNB Chain",
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "Solana",
  };
  return m[network] ?? network;
}
