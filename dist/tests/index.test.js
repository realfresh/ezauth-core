var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import jwt from "jsonwebtoken";
import faker from "faker";
import nanoid from "nanoid";
import { MongoClient } from "mongodb";
import EzAuth, { EzAuthMongoDBAdapter } from "..";
require("dotenv").config({
    path: ".env.test",
});
const SECRET_KEY = "super-secret";
const MONGO_URL = process.env.MONGO_URL;
const MONGO_DATABASE = process.env.MONGO_DATABASE;
const MONGO_COLLECTION = process.env.MONGO_COLLECTION;
describe("EZAUTH TESTS", () => {
    if (!MONGO_URL || !MONGO_DATABASE || !MONGO_COLLECTION) {
        throw new Error("Please supply process.env with MONGO_URL, MONGO_DATABASE, MONGO_COLLECTION");
    }
    let connection;
    let db;
    let auth;
    beforeAll(() => __awaiter(this, void 0, void 0, function* () {
        connection = yield MongoClient.connect(MONGO_URL, {
            useNewUrlParser: true,
        });
        db = yield connection.db(MONGO_DATABASE);
        const users = db.collection(MONGO_COLLECTION);
        yield users.deleteMany({});
        const dbAdapter = yield EzAuthMongoDBAdapter({ db, collection: MONGO_COLLECTION });
        auth = new EzAuth({
            tokenSecretKey: SECRET_KEY,
            generateId: () => nanoid(),
            generateLoginState: () => nanoid(),
            generateLoginCode: () => Math.floor(100000 + Math.random() * 900000).toString(),
            generateLoginCodeExpiry: () => Date.now() + (1000 * 60 * 10),
            generatePasswordResetCode: () => nanoid(),
            generatePasswordExpiry: () => Date.now() + (1000 * 60 * 60),
            generateVerificationCode: () => nanoid(),
            generateVerificationCodeExpiry: () => Date.now() + (1000 * 60 * 60),
            db: dbAdapter,
        });
    }));
    afterAll(() => __awaiter(this, void 0, void 0, function* () {
        yield connection.close();
    }));
    it("USER REGISTER - NO PASSWORD", () => __awaiter(this, void 0, void 0, function* () {
        const email = faker.internet.email();
        const { user } = yield auth.register({
            type: "email",
            login: email,
        });
        expect(typeof user._id).toEqual("string");
        expect(typeof user.created).toEqual("number");
        expect(user.type).toEqual("email");
        expect(user.login).toEqual(email);
        expect(typeof user.login_state).toEqual("string");
        expect(user.password).toEqual(null);
        expect(user.profile).toEqual({});
    }));
    it("USER REGISTER - PASSWORD", () => __awaiter(this, void 0, void 0, function* () {
        const email = faker.internet.email();
        const { user } = yield auth.register({
            type: "email",
            login: email,
            password: "123123",
        });
        expect(typeof user._id).toEqual("string");
        expect(typeof user.created).toEqual("number");
        expect(user.type).toEqual("email");
        expect(user.login).toEqual(email);
        expect(typeof user.login_state).toEqual("string");
        expect(typeof user.password).toEqual("string");
        expect(user.profile).toEqual({});
    }));
    it("USER REGISTER - ALREADY EXISTS", () => __awaiter(this, void 0, void 0, function* () {
        const email = faker.internet.email();
        yield auth.register({
            type: "email",
            login: email,
            password: "123123",
        });
        yield expect(auth.register({
            type: "email",
            login: email,
            password: "123123",
        })).rejects.toEqual({ code: auth.errors.user_already_exists });
    }));
    it("USER PASSWORD LOGIN - CORRECT", () => __awaiter(this, void 0, void 0, function* () {
        const email = faker.internet.email();
        yield auth.register({
            type: "email",
            login: email,
            password: "123123",
        });
        const { token } = yield auth.loginPassword({
            login: email,
            password: "123123",
        });
        expect(() => {
            jwt.verify(token, "wrong-secret");
        }).toThrow();
        const { user } = yield auth.tokenVerify({ token });
        expect(user.login).toEqual(email);
    }));
    it("USER PASSWORD LOGIN - INCORRECT", () => __awaiter(this, void 0, void 0, function* () {
        const email = faker.internet.email();
        yield auth.register({
            type: "email",
            login: email,
            password: "123123",
        });
        yield expect(auth.loginPassword({
            login: email,
            password: "321321",
        })).rejects.toEqual({
            code: auth.errors.user_incorrect_password,
        });
    }));
    it("USER PASSWORD LOGIN - NO PASSWORD", () => __awaiter(this, void 0, void 0, function* () {
        const email = faker.internet.email();
        yield auth.register({
            type: "email",
            login: email,
        });
        yield expect(auth.loginPassword({
            login: email,
            password: "321321",
        })).rejects.toEqual({
            code: auth.errors.user_no_password,
        });
    }));
    it("USER PASSWORD LOGIN - DOESNT EXIST", () => __awaiter(this, void 0, void 0, function* () {
        const email = faker.internet.email();
        yield expect(auth.loginPassword({
            login: email,
            password: "321321",
        })).rejects.toEqual({
            code: auth.errors.user_not_found,
        });
    }));
    it("USER EMAIL LOGIN", () => __awaiter(this, void 0, void 0, function* () {
        jest.setTimeout(10000);
        const login = "cpatarun@gmail.com";
        yield auth.register({
            type: "email",
            login: login,
        });
        yield expect(auth.loginEmailComplete({ login, loginCode: "" })).rejects.toEqual({
            code: auth.errors.user_login_code_inactive,
        });
        const { loginCode } = yield auth.loginEmailInit({ login });
        yield expect(auth.loginEmailComplete({ login, loginCode: "" })).rejects.toEqual({
            code: auth.errors.user_login_code_incorrect,
        });
        const { token } = yield auth.loginEmailComplete({ login, loginCode });
        const { user } = yield auth.tokenVerify({ token });
        expect(user.login).toEqual(login);
    }));
    it("USER EMAIL LOGIN - WRONG TYPE", () => __awaiter(this, void 0, void 0, function* () {
        const login = "+61466986992";
        yield auth.register({
            type: "phone",
            login: login,
        });
        yield expect(auth.loginEmailInit({ login })).rejects.toEqual({
            code: auth.errors.user_incorrect_login_type,
        });
    }));
    it("USER EMAIL VERIFICATION", () => __awaiter(this, void 0, void 0, function* () {
        jest.setTimeout(10000);
        const login = "cpatarun@gmail.com";
        yield expect(auth.emailVerificationComplete({
            login: login,
            verificationCode: "123123",
        })).rejects.toEqual({
            code: auth.errors.user_verification_inactive,
        });
        const { verificationCode } = yield auth.emailVerificationInit({ login });
        yield expect(auth.emailVerificationComplete({
            login: login,
            verificationCode: "123123",
        })).rejects.toEqual({
            code: auth.errors.user_verification_incorrect,
        });
        yield auth.emailVerificationComplete({ login, verificationCode });
        const user = yield auth.db.userFindByLogin(login);
        expect(user.verified).toEqual(true);
    }));
    it("USER REVOKE LOGIN", () => __awaiter(this, void 0, void 0, function* () {
        const login = faker.internet.email();
        yield auth.register({
            type: "email",
            login: login,
            password: "123123",
        });
        const { token } = yield auth.loginPassword({
            login: login,
            password: "123123",
        });
        const { user } = yield auth.tokenVerify({ token });
        expect(user.login).toEqual(login);
        yield auth.tokenRevoke({ login });
        yield expect(auth.tokenVerify({ token })).rejects.toEqual({
            code: auth.errors.user_login_state_invalid,
        });
    }));
    it("USER RESET PASSWORD", () => __awaiter(this, void 0, void 0, function* () {
        jest.setTimeout(10000);
        const login = faker.internet.email();
        const { user } = yield auth.register({
            type: "email",
            login: login,
            password: "123123",
        });
        const { passwordResetCode } = yield auth.resetPasswordInit({ login });
        yield expect(auth.resetPasswordComplete({
            login: login,
            password: "123123",
            passwordResetCode: "",
        })).rejects.toEqual({
            code: auth.errors.user_password_reset_incorrect,
        });
        yield auth.resetPasswordComplete({
            login: login,
            password: "123123",
            passwordResetCode: passwordResetCode,
        });
        const updatedUser = yield auth.db.userFindByLogin(login);
        expect(updatedUser.password).not.toEqual(user.password);
    }));
    it("USER UPDATE LOGIN", () => __awaiter(this, void 0, void 0, function* () {
        const login = faker.internet.email();
        const newLogin = faker.internet.email();
        const password = "123123";
        yield auth.register({
            type: "email",
            login: login,
            password: "123123",
        });
        yield auth.updateLogin({ login, newLogin });
        const { token } = yield auth.loginPassword({
            login: newLogin,
            password: password,
        });
        const { user } = yield auth.tokenVerify({ token });
        expect(user.login).toEqual(newLogin);
    }));
    it("USER UPDATE PASSWORD", () => __awaiter(this, void 0, void 0, function* () {
        const login = "cpatarun@gmail.com";
        const password = "123123";
        const user = yield auth.db.userFindByLogin(login);
        yield auth.updatePassword({ login, password });
        const updatedUser = yield auth.db.userFindByLogin(login);
        expect(user.password).not.toEqual(updatedUser.password);
        expect(user.login_state).not.toEqual(updatedUser.login_state);
    }));
    it("USER UPDATE PROFILE", () => __awaiter(this, void 0, void 0, function* () {
        const login = "cpatarun@gmail.com";
        const profile = {
            organisation_id: nanoid(),
        };
        const user = yield auth.db.userFindByLogin(login);
        yield auth.updateProfile({ login, profile });
        const updatedUser = yield auth.db.userFindByLogin(login);
        expect(updatedUser.profile).toEqual(profile);
        expect(user.profile).not.toEqual(updatedUser.profile);
    }));
    it("USER REMOVE", () => __awaiter(this, void 0, void 0, function* () {
        const login = faker.internet.email();
        yield auth.register({
            type: "email",
            login: login,
        });
        yield auth.removeUser({ login });
        const user = yield auth.db.userFindByLogin(login);
        expect(user).toEqual(null);
    }));
});
//# sourceMappingURL=index.test.js.map