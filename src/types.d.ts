
// BASE
interface EzAuthSuccess {
  outcome: 0;
}
interface EzAuthError {
  outcome: 1;
  error: string;
}

// EZ AUTH DB
type LoginTypes = "username" | "email" | "phone";
interface EzAuthUser {
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
interface EzAuthUserDB extends EzAuthUser {
  login_code: string | null;
  login_code_expiry: number | null;
  password: string | null;
  password_reset_code: string | null;
  password_reset_code_expiry: number | null;
  verification_code: string | null;
  verification_code_expiry: number | null;
}

// EZ AUTH CONFIG

interface EzAuthDBAdapter {
  userInsert: (user: EzAuthUserDB) => Promise<void>;
  userFindById: (id: string) => Promise<EzAuthUserDB | null>;
  userFindByLogin: (login: string) => Promise<EzAuthUserDB | null>;
  userUpdateById: (id: string, update: Partial<EzAuthUserDB>) => Promise<void>;
  userUpdateByLogin: (login: string, update: Partial<EzAuthUserDB>) => Promise<void>;
  userRemove: (login: string) => Promise<void>;
}

interface EzAuthOptions {
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

interface EzAuthRegisterOpts {
  type: LoginTypes;
  login: string;
  password?: string;
  profile?: EzAuthUser["profile"];
  verified?: boolean;
  generateVerificationCode?: boolean;
}
interface EzAuthRegisterResult {
  user: EzAuthUserDB;
}

interface EzAuthLoginPasswordOpts {
  login: string;
  password: string;
}
interface EzAuthLoginPasswordResult {
  token: string;
}

interface EzAuthLoginEmailInitOpts {
  login: string;
}
interface EzAuthLoginEmailInitResult {
  loginCode: string;
  loginCodeExpiry: number;
}

interface EzAuthLoginEmailCompleteOpts {
  login: string;
  loginCode: string;
}
interface EzAuthLoginEmailCompleteResult {
  token: string;
}

interface EzAuthTokenVerifyOpts {
  token: string;
}
interface EzAuthTokenVerifyResult {
  user: EzAuthUserDB;
}

interface EzAuthTokenRevokeOpts {
  login: string;
}
interface EzAuthTokenRevokeResult {}

interface EzAuthPasswordResetInitOpts {
  login: string;
}
interface EzAuthPasswordResetInitResult {
  passwordResetCode: string;
  passwordResetCodeExpiry: number;
}

interface EzAuthPasswordResetCompleteOpts {
  login: string;
  password: string;
  passwordResetCode: string;
}
interface EzAuthPasswordResetCompleteResult {}

interface EzAuthUpdateLoginOpts {
  login: string;
  newLogin: string;
}
interface EzAuthUpdateLoginResult {}

interface EzAuthUpdatePasswordOpts {
  login: string;
  password: string;
}
interface EzAuthUpdatePasswordResult {}

interface EzAuthUpdateProfileOpts {
  login: string;
  profile: EzAuthUser["profile"];
}
interface EzAuthUpdateProfileResult {
  profile: EzAuthUser["profile"];
}

interface EzAuthUserRemoveOpts {
  login: string;
}
interface EzAuthUserRemoveResult {}

interface EzAuthEmailVerificationInitOpts {
  login: string;
}

interface EzAuthEmailVerificationInitResult {
  verificationCode: string;
  verificationCodeExpiry: number;
}

interface EzAuthEmailVerificationCompleteOpts {
  login: string;
  verificationCode: string;
}
interface EzAuthEmailVerificationCompleteResult {}
