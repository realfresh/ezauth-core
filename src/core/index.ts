import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import * as T from "../types";

export class EzAuth {

  errors = {
    user_already_exists: "user_already_exists",
    user_not_found: "user_not_found",
    user_no_password: "user_no_password",
    user_incorrect_password: "user_incorrect_password",
    user_incorrect_login_type: "user_incorrect_login_type",
    user_login_code_inactive: "user_login_code_inactive",
    user_login_code_incorrect: "user_login_code_incorrect",
    user_login_code_expired: "user_login_code_expired",
    user_login_state_invalid: "user_login_state_invalid",
    user_token_invalid: "user_token_invalid",
    user_password_reset_inactive: "user_password_reset_inactive",
    user_password_reset_incorrect: "user_password_reset_incorrect",
    user_password_reset_expired: "user_password_reset_expired",
    user_incorrect_type: "user_incorrect_type",
    user_verification_inactive: "user_verification_inactive",
    user_verification_incorrect: "user_verification_incorrect",
    user_verification_expired: "user_verification_expired",
    user_verification_incorrect_type: "user_verification_incorrect_type",
  };

  opts: T.EzAuthOptions;

  constructor(opts: T.EzAuthOptions) {
    this.opts = opts;
  }
  
  get db() {
    return this.opts.db;
  }
  
  register = async (opts: T.EzAuthRegisterOpts): Promise<T.EzAuthRegisterResult> => {
    
    const existing = await this.db.userFindByLogin(opts.login);

    if (existing) {
      throw { code: this.errors.user_already_exists };
    }

    const user: T.EzAuthUserDB = {
      _id: this.opts.generateId(),
      created: Date.now(),
      type: opts.type,
      login: opts.login,
      login_state: this.opts.generateId(),
      verified: opts.verified || false,
      login_code: null,
      login_code_expiry: null,
      password: null,
      password_reset_code: null,
      password_reset_code_expiry: null,
      verification_code: null,
      verification_code_expiry: null,
      profile: opts.profile || {},
    };

    if (opts.password) {
      user.password = this.hashPassword(opts.password);
    }

    if (opts.generateVerificationCode) {
      user.verification_code = this.opts.generateVerificationCode();
      user.verification_code_expiry = this.opts.generateVerificationCodeExpiry();
    }

    await this.db.userInsert(user);

    return {
      user: user,
    };

  }

  loginPassword = async ({ login, password }: T.EzAuthLoginPasswordOpts): Promise<T.EzAuthLoginPasswordResult> => {

    const user = await this.db.userFindByLogin(login);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (!user.password) {
      throw { code: this.errors.user_no_password };
    }

    if (!bcrypt.compareSync(password, user.password)) {
      throw { code: this.errors.user_incorrect_password };
    }

    const token = this.tokenGenerate(user);

    return {
      token: token,
    };

  }

  loginEmailInit = async ({ login }: T.EzAuthLoginEmailInitOpts): Promise<T.EzAuthLoginEmailInitResult> => {

    const user = await this.db.userFindByLogin(login);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (user.type !== "email") {
      throw { code: this.errors.user_incorrect_login_type };
    }

    const loginCode = this.opts.generateLoginCode();
    const loginCodeExpiry = this.opts.generateLoginCodeExpiry();

    await this.db.userUpdateById(user._id, {
      login_code: loginCode,
      login_code_expiry: loginCodeExpiry,
    });

    return {
      loginCode: loginCode,
      loginCodeExpiry: loginCodeExpiry,
    };

  }

  loginEmailComplete = async ({ login, loginCode }: T.EzAuthLoginEmailCompleteOpts): Promise<T.EzAuthLoginEmailCompleteResult> => {

    const user = await this.db.userFindByLogin(login);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (user.login_code === null) {
      throw { code: this.errors.user_login_code_inactive };
    }

    if (user.login_code_expiry === null || Date.now() > user.login_code_expiry) {
      throw { code: this.errors.user_login_code_expired };
    }

    if (user.login_code !== loginCode) {
      throw { code: this.errors.user_login_code_incorrect };
    }

    await this.db.userUpdateById(user._id, {
      login_code: null,
      login_code_expiry: null,
    });

    const token = this.tokenGenerate(user);

    return {
      token: token,
    };

  }

  tokenVerify = async ({ token }: T.EzAuthTokenVerifyOpts): Promise<T.EzAuthTokenVerifyResult> => {

    let decoded;
    try {
      decoded = this.tokenVerifyBasic(token);
    }
    catch (e) {
      throw { code: this.errors.user_token_invalid };
    }

    const user = await this.db.userFindById(decoded._id);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (user.login_state !== decoded.login_state) {
      throw { code: this.errors.user_login_state_invalid };
    }

    return {
      user: user,
    };

  }

  tokenRevoke = async ({ login }: T.EzAuthTokenRevokeOpts): Promise<T.EzAuthTokenRevokeResult> => {

    await this.db.userUpdateByLogin(login, {
      login_state: this.opts.generateLoginState(),
    });

    return { outcome: 0 };

  }
  
  resetPasswordInit = async ({ login }: T.EzAuthPasswordResetInitOpts): Promise<T.EzAuthPasswordResetInitResult> => {

    const user = await this.db.userFindByLogin(login);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    const passwordResetCode = this.opts.generatePasswordResetCode();
    const passwordResetCodeExpiry = this.opts.generatePasswordExpiry();

    await this.db.userUpdateById(user._id, {
      password_reset_code: passwordResetCode,
      password_reset_code_expiry: passwordResetCodeExpiry,
    });

    return {
      passwordResetCode: passwordResetCode,
      passwordResetCodeExpiry: passwordResetCodeExpiry,
    };

  }

  resetPasswordComplete = async ({ login, password, passwordResetCode }: T.EzAuthPasswordResetCompleteOpts): Promise<T.EzAuthPasswordResetCompleteResult> => {

    const user = await this.db.userFindByLogin(login);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (user.password_reset_code === null) {
      throw { code: this.errors.user_login_code_inactive };
    }

    if (user.password_reset_code_expiry === null || Date.now() > user.password_reset_code_expiry) {
      throw { code: this.errors.user_password_reset_expired };
    }

    if (user.password_reset_code !== passwordResetCode) {
      throw { code: this.errors.user_password_reset_incorrect };
    }

    await this.db.userUpdateById(user._id, {
      password: this.hashPassword(password),
      password_reset_code: null,
      password_reset_code_expiry: null,
    });

    return {
      outcome: 0,
    };

  }

  updateLogin = async ({ login, newLogin }: T.EzAuthUpdateLoginOpts): Promise<T.EzAuthUpdateLoginResult> => {

    const existing = await this.db.userFindByLogin(newLogin);

    if (existing) {
      return {
        outcome: 1,
        error: this.errors.user_already_exists,
      };
    }

    await this.db.userUpdateByLogin(login, {
      login: newLogin,
      login_state: this.opts.generateLoginState(),
    });

    return { outcome: 0 };

  }

  updatePassword = async ({ login, password }: T.EzAuthUpdatePasswordOpts): Promise<T.EzAuthUpdatePasswordResult> => {

    await this.db.userUpdateByLogin(login, {
      password: this.hashPassword(password),
      login_state: this.opts.generateLoginState(),
    });

    return {
      outcome: 0,
    };

  }

  updateProfile = async ({ login, profile }: T.EzAuthUpdateProfileOpts): Promise<T.EzAuthUpdateProfileResult> => {

    const user = await this.db.userFindByLogin(login);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    const newProfile = {
      ...(user.profile || {}),
      ...(profile || {}),
    };

    await this.db.userUpdateByLogin(login, {
      profile: newProfile,
    });

    return {
      profile: newProfile,
    };

  }

  removeUser =  async ({ login }: T.EzAuthUserRemoveOpts): Promise<T.EzAuthUserRemoveResult> => {

    await this.db.userRemove(login);

    return {
      outcome: 0,
    };

  }

  emailVerificationInit = async ({ login }: T.EzAuthEmailVerificationInitOpts): Promise<T.EzAuthEmailVerificationInitResult> => {

    const user = await this.db.userFindByLogin(login);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (user.type !== "email") {
      throw { code: this.errors.user_incorrect_type };
    }

    const verificationCode = this.opts.generateVerificationCode();
    const verificationCodeExpiry = this.opts.generateVerificationCodeExpiry();

    await this.db.userUpdateById(user._id, {
      verification_code: verificationCode,
      verification_code_expiry: verificationCodeExpiry,
    });

    return {
      verificationCode: verificationCode,
      verificationCodeExpiry: verificationCodeExpiry,
    };

  }

  emailVerificationComplete = async ({ login, verificationCode }: T.EzAuthEmailVerificationCompleteOpts): Promise<T.EzAuthEmailVerificationCompleteResult> => {

    const user = await this.db.userFindByLogin(login);

    if (!user) {
      throw { code: this.errors.user_not_found };
    }

    if (user.verification_code === null) {
      throw { code: this.errors.user_verification_inactive };
    }

    if (user.verification_code_expiry === null || Date.now() > user.verification_code_expiry) {
      throw { code: this.errors.user_verification_expired };
    }

    if (user.verification_code !== verificationCode) {
      throw { code: this.errors.user_verification_incorrect };
    }

    await this.db.userUpdateById(user._id, {
      verified: true,
      verification_code: null,
      verification_code_expiry: null,
    });

    return {
      outcome: 0,
    };

  }

  private tokenVerifyBasic = (token: string): T.EzAuthUser => {
    return jwt.verify(token, this.opts.tokenSecretKey) as T.EzAuthUser;
  }

  private tokenGenerate = (user: T.EzAuthUserDB) => {
    this.userMakeSafe(user);
    return jwt.sign(user, this.opts.tokenSecretKey, {
      expiresIn: this.opts.tokenExpiry || "1h",
    });
  }

  private userMakeSafe = (user: T.EzAuthUserDB): T.EzAuthUser => {
    delete user.password;
    delete user.login_code;
    delete user.login_code_expiry;
    return user;
  }

  private hashPassword = (password: string) => {
    return bcrypt.hashSync(password, this.opts.passwordSaltRounds || 12);
  }

}
