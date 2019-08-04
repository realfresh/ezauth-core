import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import * as T from "../types";
import nanoid from "nanoid";

export class EzAuth {

  readonly errors = {
    update_login_already_exists: "update_login_already_exists",
    user_not_found: "user_not_found",

    register_missing_identifier: "register_missing_identifier",
    register_already_exists: "register_already_exists",

    login_password_none: "login_password_none",
    login_password_incorrect: "user_incorrect_password",
    login_code_inactive: "user_login_code_inactive",
    login_code_incorrect: "user_login_code_incorrect",
    login_code_expired: "user_login_code_expired",

    user_auth_state_invalid: "user_auth_state_invalid",
    user_token_invalid: "user_token_invalid",

    password_reset_inactive: "user_password_reset_inactive",
    password_reset_incorrect: "user_password_reset_incorrect",
    password_reset_expired: "user_password_reset_expired",

    user_incorrect_type: "user_incorrect_type",

    verification_inactive: "user_verification_inactive",
    verification_incorrect: "user_verification_incorrect",
    verification_expired: "user_verification_expired",
  };
  readonly opts: T.Options;
  readonly generate: T.Generators;
  readonly db: T.DBAdapter;

  constructor(opts: T.Options) {

    this.opts = opts;
    this.db = opts.db;
    this.generate = {
      userId: () => nanoid(),
      authState: () => nanoid(),
      loginCode: () => Math.floor(100000 + Math.random() * 900000).toString(),
      loginCodeExpiry: () => Date.now() + (1000 * 60 * 10),
      passwordResetCode: () => nanoid(),
      passwordResetCodeExpiry: () => Date.now() + (1000 * 60 * 60),
      verificationCode: () => nanoid(),
      verificationCodeExpiry: () => Date.now() + (1000 * 60 * 60),
      ...opts.generate,
    };

  }
  
  register = async (opts: T.RegisterOpts): Promise<T.RegisterResult> => {

    const { username, email, phone } = opts;

    if (!username && !email && !phone) {
      throw { code: this.errors.register_missing_identifier };
    }

    const existing = await this.db.find({ username, email, phone }, true);

    if (existing) {
      throw { code: this.errors.register_already_exists };
    }

    const user: T.User = {
      _id: this.generate.userId(),
      created: Date.now(),
      auth_state: this.generate.authState(),
      username: username,
      email: email,
      phone: phone,
      email_verified: false,
      phone_verified: false,
      login_code: null,
      login_code_expiry: null,
      password: null,
      password_reset_code: null,
      password_reset_code_expiry: null,
      verification_code: null,
      verification_code_expiry: null,
      data: opts.data || {},
    };

    if (opts.password) {
      user.password = this.hashPassword(opts.password);
    }

    if (opts.generateVerificationCode) {
      user.verification_code = this.generate.verificationCode();
      user.verification_code_expiry = this.generate.verificationCodeExpiry();
    }

    await this.db.insert(user);

    return {
      user: user,
    };

  }

  loginPassword = async (opts: T.LoginPasswordOpts): Promise<T.LoginPasswordResult> => {

    const { password } = opts;

    const query = this.queryFromOpts(opts);

    const user = await this.db.find(query);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (!user.password) {
      throw { code: this.errors.login_password_none };
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      throw { code: this.errors.login_password_incorrect };
    }

    const token = await this.tokenGenerate(user);

    return {
      token: token,
    };

  }

  loginCodeInit = async (opts: T.LoginEmailInitOpts): Promise<T.LoginEmailInitResult> => {

    const { send } = opts;

    const query = this.queryFromOpts(opts);

    const user = await this.db.find(query);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    const loginCode = this.generate.loginCode();
    const loginCodeExpiry = this.generate.loginCodeExpiry();

    await this.db.update({ _id: user._id }, {
      login_code: loginCode,
      login_code_expiry: loginCodeExpiry,
    });

    if (send && this.opts.sendLoginCode) {
      await this.opts.sendLoginCode(user, loginCode, loginCodeExpiry);
    }

    return {
      loginCode: loginCode,
      loginCodeExpiry: loginCodeExpiry,
    };

  }

  loginCodeComplete = async (opts: T.LoginEmailCompleteOpts): Promise<T.LoginEmailCompleteResult> => {

    const { loginCode } = opts;

    const query = this.queryFromOpts(opts);

    const user = await this.db.find(query);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (user.login_code === null) {
      throw { code: this.errors.login_code_inactive };
    }

    if (user.login_code_expiry === null || Date.now() > user.login_code_expiry) {
      throw { code: this.errors.login_code_expired };
    }

    if (user.login_code !== loginCode) {
      throw { code: this.errors.login_code_incorrect };
    }

    await this.db.update({ _id: user._id }, {
      login_code: null,
      login_code_expiry: null,
    });

    const token = await this.tokenGenerate(user);

    return {
      token: token,
    };

  }

  tokenVerify = async ({ token }: T.TokenVerifyOpts): Promise<T.TokenVerifyResult> => {

    let decoded;
    try {
      decoded = await this.tokenVerifyBasic(token);
    }
    catch (e) {
      throw { code: this.errors.user_token_invalid };
    }

    const user = await this.db.find({ _id: decoded.sub });

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (user.auth_state !== decoded.auth_state) {
      throw { code: this.errors.user_token_invalid };
    }

    return {
      user: user,
      decoded: decoded,
    };

  }

  tokenRevoke = async (opts: T.TokenRevokeOpts): Promise<T.TokenRevokeResult> => {

    const query = this.queryFromOpts(opts);

    await this.db.update(query, {
      auth_state: this.generate.authState(),
    });

    return {};

  }
  
  resetPasswordInit = async (opts: T.PasswordResetInitOpts): Promise<T.PasswordResetInitResult> => {

    const code = this.generate.passwordResetCode();
    const expiry = this.generate.passwordResetCodeExpiry();

    const query = this.queryFromOpts(opts);

    await this.db.update(query, {
      password_reset_code: code,
      password_reset_code_expiry: expiry,
    });

    return { code, expiry };

  }

  resetPasswordComplete = async (opts: T.PasswordResetCompleteOpts): Promise<T.PasswordResetCompleteResult> => {

    const { password, code } = opts;

    const query = this.queryFromOpts(opts);

    const user = await this.db.find(query);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (user.password_reset_code === null) {
      throw { code: this.errors.password_reset_inactive };
    }

    if (user.password_reset_code_expiry === null || Date.now() > user.password_reset_code_expiry) {
      throw { code: this.errors.password_reset_expired };
    }

    if (user.password_reset_code !== code) {
      throw { code: this.errors.password_reset_incorrect };
    }

    await this.db.update(query, {
      password: this.hashPassword(password),
      password_reset_code: null,
      password_reset_code_expiry: null,
    });

    return {};

  }

  updateLogin = async (opts: T.UpdateLoginOpts): Promise<T.UpdateLoginResult> => {

    const query = this.queryFromOpts(opts);
    const checkQuery: T.UserQuery = {};
    const update: Partial<T.User> = {};

    if (opts.newUsername) {
      checkQuery.username = opts.newUsername;
      update.username = opts.newUsername;
    }
    if (opts.newEmail) {
      checkQuery.email = opts.newEmail;
      update.email = opts.newEmail;
    }
    if (opts.newPhone) {
      checkQuery.phone = opts.newPhone;
      update.phone = opts.phone;
    }

    const existing = await this.db.find(checkQuery, true);

    if (existing) {
      throw { code: this.errors.update_login_already_exists };
    }

    await this.db.update(query, update);

    return {};

  }

  updatePassword = async (opts: T.UpdatePasswordOpts): Promise<T.UpdatePasswordResult> => {

    const query = this.queryFromOpts(opts);

    await this.db.update(query, {
      password: this.hashPassword(opts.password),
      auth_state: this.generate.authState(),
    });

    return {};

  }

  updateData = async (opts: T.UpdateDataOpts): Promise<T.UpdateDataResult> => {

    const query = this.queryFromOpts(opts);

    const user = await this.db.find(query);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    const data = {
      ...(user.data || {}),
      ...(opts.data || {}),
    };

    await this.db.update({ _id: user._id }, { data });

    return { data };

  }

  removeUser =  async (opts: T.UserRemoveOpts): Promise<T.UserRemoveResult> => {

    const query = this.queryFromOpts(opts);

    await this.db.remove(query);

    return {};

  }

  verificationInit = async (opts: T.VerificationInitOpts): Promise<T.VerificationInitResult> => {

    const query = this.queryFromOpts(opts);

    const user = await this.db.find(query);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    const code = this.generate.verificationCode();
    const expiry = this.generate.verificationCodeExpiry();

    await this.db.update({ _id: user._id }, {
      verification_code: code,
      verification_code_expiry: expiry,
    });

    return { code, expiry };

  }

  verificationComplete = async (opts: T.VerificationCompleteOpts): Promise<T.VerificationCompleteResult> => {

    const { type, code } = opts;

    const query = this.queryFromOpts(opts);

    const user = await this.db.find(query);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (user.verification_code === null) {
      throw { code: this.errors.verification_inactive };
    }

    if (user.verification_code_expiry === null || Date.now() > user.verification_code_expiry) {
      throw { code: this.errors.verification_expired };
    }

    if (user.verification_code !== code) {
      throw { code: this.errors.verification_incorrect };
    }

    const update: Partial<T.User> = {
      verification_code: null,
      verification_code_expiry: null,
    };

    if (type === "email") {
      update.email_verified = true;
    }
    else if (type === "phone") {
      update.phone_verified = true;
    }

    await this.db.update({ _id: user._id }, update);

    return {};

  }

  private queryFromOpts = ({ _id, username, email, phone }: T.UserQuery) => {
    return { _id, username, email, phone };
  }

  private tokenVerifyBasic = async (token: string): Promise<T.UserToken> => {
    const verifyKey = this.opts.tokenPublicKey || this.opts.tokenSecretKey;
    return jwt.verify(token, verifyKey, {
      algorithms: [ this.opts.tokenAlgorithm ],
    }) as T.UserToken;
  }

  private tokenGenerate = async (user: T.User): Promise<string> => {

    const data = this.userToTokenData(user);

    return jwt.sign(data, this.opts.tokenSecretKey, {
      expiresIn: this.opts.tokenExpiry || "1h",
      algorithm: this.opts.tokenAlgorithm,
    });

  }

  private userToTokenData = (user: T.User): T.UserToken => {
    const tokenData: T.UserToken = {
      sub: user._id,
      created: user.created,
      auth_state: user.auth_state,
      data: user.data,
    };
    if (user.username) {
      tokenData.preferred_username = user.username;
    }
    if (user.email) {
      tokenData.email = user.email;
      tokenData.email_verified = user.email_verified || false;
    }
    if (user.phone) {
      tokenData.phone_number = user.phone;
      tokenData.phone_number_verified = user.phone_verified || false;
    }
    return tokenData;
  }

  private hashPassword = (password: string) => {
    return bcrypt.hashSync(password, this.opts.passwordSaltRounds || 12);
  }

}
