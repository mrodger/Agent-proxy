declare module 'speakeasy' {
  interface GenerateSecretOptions {
    name?: string;
    issuer?: string;
    length?: number;
  }
  
  interface GenerateSecretResult {
    secret: string;
    base32: string;
    otpauth_url: string;
  }
  
  interface TOTPVerifyOptions {
    secret: string;
    token: string;
    encoding?: string;
    window?: number;
  }
  
  export const generateSecret: (options: GenerateSecretOptions) => GenerateSecretResult;
  export const totp: {
    verify: (options: TOTPVerifyOptions) => boolean | null;
  };
}
