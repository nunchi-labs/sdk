declare module "./coins_wasm/coins_wasm.js" {
  export default function init(input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module): Promise<unknown>;
  export function parse_block(participants: number, bytes: Uint8Array): unknown;
  export function parse_consensus_message(identity: Uint8Array, participants: number, bytes: Uint8Array): unknown;
  export function parse_finalized(identity: Uint8Array, participants: number, bytes: Uint8Array): unknown;
  export function parse_notarized(identity: Uint8Array, participants: number, bytes: Uint8Array): unknown;
  export function parse_seed(identity: Uint8Array, bytes: Uint8Array): unknown;
}
