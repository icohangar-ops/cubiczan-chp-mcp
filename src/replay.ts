/**
 * In-process nonce ledger for approval receipts.
 *
 * A receipt is single-use. Replaying the same nonce — even with a valid MAC
 * and unexpired window — is a deny. Persistence across processes is out of
 * scope for this MCP transport; callers that share workers must inject a
 * store that is safe for that topology.
 */

export interface ReplayRecord {
  nonce: string;
  consumed_at: string;
  args_hash: string;
  tool: string;
  resource: string;
}

export interface ReplayStore {
  seen(nonce: string): boolean;
  consume(record: ReplayRecord): void;
}

export class InMemoryReplayStore implements ReplayStore {
  private readonly used = new Map<string, ReplayRecord>();

  seen(nonce: string): boolean {
    return this.used.has(nonce);
  }

  consume(record: ReplayRecord): void {
    this.used.set(record.nonce, record);
  }

  get(nonce: string): ReplayRecord | undefined {
    return this.used.get(nonce);
  }

  get size(): number {
    return this.used.size;
  }
}
