
// SCHEMA

interface UserData {
  [key: string]: any;
}

export interface UserToken {
  sub: string;
  created: number;
  auth_state: string;
  preferred_username?: string;
  email?: string;
  email_verified?: boolean;
  phone_number?: string;
  phone_number_verified?: boolean;
  data?: UserData;
}

export interface User {
  _id: string;
  created: number;
  username?: string;
  email?: string;
  phone?: string;
  email_verified?: boolean;
  phone_verified?: boolean;
  auth_state: string;
  login_code: string | null;
  login_code_expiry: number | null;
  password: string | null;
  password_reset_code: string | null;
  password_reset_code_expiry: number | null;
  verification_code: string | null;
  verification_code_expiry: number | null;
  data?: UserData;
}

export interface UserQuery {
  _id?: string;
  username?: string;
  email?: string;
  phone?: string;
}

// CONFIG

export interface DBAdapter<UserExt extends User = User> {
  insert: (user: User) => Promise<UserExt>;
  find: (query: UserQuery, checkAll?: boolean) => Promise<UserExt | null>;
  update: (query: UserQuery, update: Partial<User | UserExt>) => Promise<void>;
  remove: (query: UserQuery) => Promise<void>;
}

export interface Generators {
  userId: () => string;
  authState: () => string;
  loginCode: () => string;
  loginCodeExpiry: () => number;
  passwordResetCode: () => string;
  passwordResetCodeExpiry: () => number;
  verificationCode: () => string;
  verificationCodeExpiry: () => number;
}

export interface Options<UserExt extends User = User> {
  tokenAlgorithm: string;
  tokenSecretKey: string;
  tokenPublicKey?: string;
  tokenExpiry?: number;
  passwordSaltRounds?: number;
  generate?: Partial<Generators>;
  sendLoginCode?: (user: UserExt, code: string, expiry: number) => Promise<void>;
  sendVerificationCode?: (user: UserExt, code: string, expiry: number) => Promise<void>;
  sendPasswordResetCode?: (user: UserExt, code: string, expiry: number) => Promise<void>;
  db: DBAdapter<UserExt>;
}

// FUNCTIONS

export interface RegisterOpts {
  username?: string;
  email?: string;
  phone?: string;
  email_verified?: boolean;
  phone_verified?: boolean;
  password?: string;
  data?: User["data"];
  generateVerificationCode?: boolean;
}
export interface RegisterResult<UserExt> {
  user: UserExt;
}

export interface LoginPasswordOpts extends UserQuery {
  password: string;
}
export interface LoginPasswordResult {
  token: string;
}

export interface LoginEmailInitOpts extends UserQuery {
  send?: boolean;
}
export interface LoginEmailInitResult {
  loginCode: string;
  loginCodeExpiry: number;
}

export interface LoginEmailCompleteOpts extends UserQuery {
  loginCode: string;
}
export interface LoginEmailCompleteResult {
  token: string;
}

export interface VerificationInitOpts extends UserQuery {
  // send?: boolean;
}
export interface VerificationInitResult {
  code: string;
  expiry: number;
}

export interface VerificationCompleteOpts extends UserQuery {
  type: "email" | "phone";
  code: string;
}
export interface VerificationCompleteResult {}

export interface TokenVerifyOpts {
  token: string;
}
export interface TokenVerifyResult<UserExt> {
  user: UserExt;
  decoded: UserToken;
}

export interface TokenRevokeOpts extends UserQuery {

}
export interface TokenRevokeResult {}

export interface PasswordResetInitOpts extends UserQuery {
  send?: boolean;
}
export interface PasswordResetInitResult {
  code: string;
  expiry: number;
}

export interface PasswordResetCompleteOpts extends UserQuery {
  password: string;
  code: string;
}
export interface PasswordResetCompleteResult {}

export interface UpdateLoginOpts extends UserQuery {
  newUsername?: string;
  newEmail?: string;
  newPhone?: string;
}
export interface UpdateLoginResult {}

export interface UpdatePasswordOpts extends UserQuery {
  password: string;
}
export interface UpdatePasswordResult {}

export interface UpdateDataOpts extends UserQuery {
  data: User["data"];
}
export interface UpdateDataResult {
  data: User["data"];
}

export interface UserRemoveOpts extends UserQuery {}
export interface UserRemoveResult {}
