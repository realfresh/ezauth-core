
// BASE
export interface EzAuthSuccess {
  outcome: 0;
}
export interface EzAuthError {
  outcome: 1;
  error: string;
}

// EZ AUTH DB
export type LoginTypes = "username" | "email" | "phone";
export interface EzAuthUser {
  _id: string;
  created: number;
  type: LoginTypes;
  login: string; // username, email, phone
  login_state: string;
  verified: boolean;
  profile: {
    [key: string]: any;
  };
}
export interface EzAuthUserDB extends EzAuthUser {
  login_code: string | null;
  login_code_expiry: number | null;
  password: string | null;
  password_reset_code: string | null;
  password_reset_code_expiry: number | null;
  verification_code: string | null;
  verification_code_expiry: number | null;
}

// EZ AUTH CONFIG

export interface EzAuthDBAdapter {
  userInsert: (user: EzAuthUserDB) => Promise<void>;
  userFindById: (id: string) => Promise<EzAuthUserDB | null>;
  userFindByLogin: (login: string) => Promise<EzAuthUserDB | null>;
  userUpdateById: (id: string, update: Partial<EzAuthUserDB>) => Promise<void>;
  userUpdateByLogin: (login: string, update: Partial<EzAuthUserDB>) => Promise<void>;
  userRemove: (login: string) => Promise<void>;
}

export interface EzAuthOptions {
  tokenSecretKey: string;
  tokenExpiry?: number;
  passwordSaltRounds?: number;
  generateId: () => string;
  generateLoginState: () => string;
  generateLoginCode: () => string;
  generateLoginCodeExpiry: () => number;
  generatePasswordResetCode: () => string;
  generatePasswordExpiry: () => number;
  generateVerificationCode: () => string;
  generateVerificationCodeExpiry: () => number;
  db: EzAuthDBAdapter;
}

// EZ AUTH FUNCTIONS

export interface EzAuthRegisterOpts {
  type: LoginTypes;
  login: string;
  password?: string;
  profile?: EzAuthUser["profile"];
  verified?: boolean;
  generateVerificationCode?: boolean;
}
export interface EzAuthRegisterResult {
  user: EzAuthUserDB;
}

export interface EzAuthLoginPasswordOpts {
  login: string;
  password: string;
}
export interface EzAuthLoginPasswordResult {
  token: string;
}

export interface EzAuthLoginEmailInitOpts {
  login: string;
}
export interface EzAuthLoginEmailInitResult {
  loginCode: string;
  loginCodeExpiry: number;
}

export interface EzAuthLoginEmailCompleteOpts {
  login: string;
  loginCode: string;
}
export interface EzAuthLoginEmailCompleteResult {
  token: string;
}

export interface EzAuthTokenVerifyOpts {
  token: string;
}
export interface EzAuthTokenVerifyResult {
  user: EzAuthUserDB;
}

export interface EzAuthTokenRevokeOpts {
  login: string;
}
export interface EzAuthTokenRevokeResult {}

export interface EzAuthPasswordResetInitOpts {
  login: string;
}
export interface EzAuthPasswordResetInitResult {
  passwordResetCode: string;
  passwordResetCodeExpiry: number;
}

export interface EzAuthPasswordResetCompleteOpts {
  login: string;
  password: string;
  passwordResetCode: string;
}
export interface EzAuthPasswordResetCompleteResult {}

export interface EzAuthUpdateLoginOpts {
  login: string;
  newLogin: string;
}
export interface EzAuthUpdateLoginResult {}

export interface EzAuthUpdatePasswordOpts {
  login: string;
  password: string;
}
export interface EzAuthUpdatePasswordResult {}

export interface EzAuthUpdateProfileOpts {
  login: string;
  profile: EzAuthUser["profile"];
}
export interface EzAuthUpdateProfileResult {
  profile: EzAuthUser["profile"];
}

export interface EzAuthUserRemoveOpts {
  login: string;
}
export interface EzAuthUserRemoveResult {}

export interface EzAuthEmailVerificationInitOpts {
  login: string;
}

export interface EzAuthEmailVerificationInitResult {
  verificationCode: string;
  verificationCodeExpiry: number;
}

export interface EzAuthEmailVerificationCompleteOpts {
  login: string;
  verificationCode: string;
}
export interface EzAuthEmailVerificationCompleteResult {}
