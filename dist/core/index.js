"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
class EzAuth {
    constructor(opts) {
        this.errors = {
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
        this.register = (opts) => __awaiter(this, void 0, void 0, function* () {
            const existing = yield this.db.userFindByLogin(opts.login);
            if (existing) {
                throw { code: this.errors.user_already_exists };
            }
            const user = {
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
            yield this.db.userInsert(user);
            return {
                user: user,
            };
        });
        this.loginPassword = ({ login, password }) => __awaiter(this, void 0, void 0, function* () {
            const user = yield this.db.userFindByLogin(login);
            if (!user) {
                throw { code: this.errors.user_not_found };
            }
            if (!user.password) {
                throw { code: this.errors.user_no_password };
            }
            if (!bcrypt_1.default.compareSync(password, user.password)) {
                throw { code: this.errors.user_incorrect_password };
            }
            const token = this.tokenGenerate(user);
            return {
                token: token,
            };
        });
        this.loginEmailInit = ({ login }) => __awaiter(this, void 0, void 0, function* () {
            const user = yield this.db.userFindByLogin(login);
            if (!user) {
                throw { code: this.errors.user_not_found };
            }
            if (user.type !== "email") {
                throw { code: this.errors.user_incorrect_login_type };
            }
            const loginCode = this.opts.generateLoginCode();
            const loginCodeExpiry = this.opts.generateLoginCodeExpiry();
            yield this.db.userUpdateById(user._id, {
                login_code: loginCode,
                login_code_expiry: loginCodeExpiry,
            });
            return {
                loginCode: loginCode,
                loginCodeExpiry: loginCodeExpiry,
            };
        });
        this.loginEmailComplete = ({ login, loginCode }) => __awaiter(this, void 0, void 0, function* () {
            const user = yield this.db.userFindByLogin(login);
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
            yield this.db.userUpdateById(user._id, {
                login_code: null,
                login_code_expiry: null,
            });
            const token = this.tokenGenerate(user);
            return {
                token: token,
            };
        });
        this.tokenVerify = ({ token }) => __awaiter(this, void 0, void 0, function* () {
            let decoded;
            try {
                decoded = this.tokenVerifyBasic(token);
            }
            catch (e) {
                throw { code: this.errors.user_token_invalid };
            }
            const user = yield this.db.userFindById(decoded._id);
            if (!user) {
                throw { code: this.errors.user_not_found };
            }
            if (user.login_state !== decoded.login_state) {
                throw { code: this.errors.user_login_state_invalid };
            }
            return {
                user: user,
            };
        });
        this.tokenRevoke = ({ login }) => __awaiter(this, void 0, void 0, function* () {
            yield this.db.userUpdateByLogin(login, {
                login_state: this.opts.generateLoginState(),
            });
            return { outcome: 0 };
        });
        this.resetPasswordInit = ({ login }) => __awaiter(this, void 0, void 0, function* () {
            const user = yield this.db.userFindByLogin(login);
            if (!user) {
                throw { code: this.errors.user_not_found };
            }
            const passwordResetCode = this.opts.generatePasswordResetCode();
            const passwordResetCodeExpiry = this.opts.generatePasswordExpiry();
            yield this.db.userUpdateById(user._id, {
                password_reset_code: passwordResetCode,
                password_reset_code_expiry: passwordResetCodeExpiry,
            });
            return {
                passwordResetCode: passwordResetCode,
                passwordResetCodeExpiry: passwordResetCodeExpiry,
            };
        });
        this.resetPasswordComplete = ({ login, password, passwordResetCode }) => __awaiter(this, void 0, void 0, function* () {
            const user = yield this.db.userFindByLogin(login);
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
            yield this.db.userUpdateById(user._id, {
                password: this.hashPassword(password),
                password_reset_code: null,
                password_reset_code_expiry: null,
            });
            return {
                outcome: 0,
            };
        });
        this.updateLogin = ({ login, newLogin }) => __awaiter(this, void 0, void 0, function* () {
            const existing = yield this.db.userFindByLogin(newLogin);
            if (existing) {
                return {
                    outcome: 1,
                    error: this.errors.user_already_exists,
                };
            }
            yield this.db.userUpdateByLogin(login, {
                login: newLogin,
                login_state: this.opts.generateLoginState(),
            });
            return { outcome: 0 };
        });
        this.updatePassword = ({ login, password }) => __awaiter(this, void 0, void 0, function* () {
            yield this.db.userUpdateByLogin(login, {
                password: this.hashPassword(password),
                login_state: this.opts.generateLoginState(),
            });
            return {
                outcome: 0,
            };
        });
        this.updateProfile = ({ login, profile }) => __awaiter(this, void 0, void 0, function* () {
            const user = yield this.db.userFindByLogin(login);
            if (!user) {
                throw { code: this.errors.user_not_found };
            }
            const newProfile = Object.assign({}, (user.profile || {}), (profile || {}));
            yield this.db.userUpdateByLogin(login, {
                profile: newProfile,
            });
            return {
                profile: newProfile,
            };
        });
        this.removeUser = ({ login }) => __awaiter(this, void 0, void 0, function* () {
            yield this.db.userRemove(login);
            return {
                outcome: 0,
            };
        });
        this.emailVerificationInit = ({ login }) => __awaiter(this, void 0, void 0, function* () {
            const user = yield this.db.userFindByLogin(login);
            if (!user) {
                throw { code: this.errors.user_not_found };
            }
            if (user.type !== "email") {
                throw { code: this.errors.user_incorrect_type };
            }
            const verificationCode = this.opts.generateVerificationCode();
            const verificationCodeExpiry = this.opts.generateVerificationCodeExpiry();
            yield this.db.userUpdateById(user._id, {
                verification_code: verificationCode,
                verification_code_expiry: verificationCodeExpiry,
            });
            return {
                verificationCode: verificationCode,
                verificationCodeExpiry: verificationCodeExpiry,
            };
        });
        this.emailVerificationComplete = ({ login, verificationCode }) => __awaiter(this, void 0, void 0, function* () {
            const user = yield this.db.userFindByLogin(login);
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
            yield this.db.userUpdateById(user._id, {
                verified: true,
                verification_code: null,
                verification_code_expiry: null,
            });
            return {
                outcome: 0,
            };
        });
        this.tokenVerifyBasic = (token) => {
            return jsonwebtoken_1.default.verify(token, this.opts.tokenSecretKey);
        };
        this.tokenGenerate = (user) => {
            this.userMakeSafe(user);
            return jsonwebtoken_1.default.sign(user, this.opts.tokenSecretKey, {
                expiresIn: this.opts.tokenExpiry || "1h",
            });
        };
        this.userMakeSafe = (user) => {
            delete user.password;
            delete user.login_code;
            delete user.login_code_expiry;
            return user;
        };
        this.hashPassword = (password) => {
            return bcrypt_1.default.hashSync(password, this.opts.passwordSaltRounds || 12);
        };
        this.opts = opts;
    }
    get db() {
        return this.opts.db;
    }
}
exports.EzAuth = EzAuth;
//# sourceMappingURL=index.js.map