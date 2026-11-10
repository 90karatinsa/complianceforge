// SPDX-License-Identifier: MIT

declare module 'pg' {
  interface QueryResult<Row = unknown> {
    readonly rows: readonly Row[];
    readonly rowCount: number;
  }

  interface PoolConfig {
    readonly connectionString: string;
  }

  export interface PoolClient {
    query<Row = unknown>(queryText: string, values?: readonly unknown[]): Promise<QueryResult<Row>>;
    release(): void;
  }

  export class Pool {
    constructor(config: PoolConfig);
    connect(): Promise<PoolClient>;
    query<Row = unknown>(queryText: string, values?: readonly unknown[]): Promise<QueryResult<Row>>;
    end(): Promise<void>;
  }
}
