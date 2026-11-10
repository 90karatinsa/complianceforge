// SPDX-License-Identifier: MIT

declare module 'keytar' {
  const keytar: {
    setPassword(service: string, account: string, password: string): Promise<void>;
    getPassword(service: string, account: string): Promise<string | null>;
    deletePassword(service: string, account: string): Promise<boolean>;
  };
  export default keytar;
}

declare module 'undici' {
  interface AgentOptions {
    connect?: {
      lookup?: (
        hostname: string,
        options: { family?: number; hints?: number; all?: boolean },
        callback: (...args: unknown[]) => void
      ) => void;
    };
  }

  class AgentImpl {
    constructor(options?: AgentOptions);
    dispatch: (...args: unknown[]) => unknown;
    close: () => Promise<void>;
    destroy: (error?: Error) => Promise<void>;
  }

  export const Agent: typeof AgentImpl;
}

declare module '@aws-sdk/client-secrets-manager' {
  interface SecretsManagerClientConfig {
    region?: string;
    endpoint?: string;
    credentials?: unknown;
  }

  export class SecretsManagerClient {
    constructor(config?: SecretsManagerClientConfig);
    send(command: GetSecretValueCommand): Promise<{ SecretString?: string; SecretBinary?: Uint8Array }>;
  }

  export class GetSecretValueCommand {
    readonly input: { SecretId: string };
    constructor(input: { SecretId: string });
  }
}
