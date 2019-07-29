import jwt from "jsonwebtoken";
import faker from "faker";
import nanoid from "nanoid";
import {Db, MongoClient} from "mongodb";
import EzAuth, {EzAuthMongoDBAdapter} from "..";

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

  let connection: MongoClient;
  let db: Db;
  let auth: EzAuth;

  beforeAll(async () => {

    connection = await MongoClient.connect(MONGO_URL, {
      useNewUrlParser: true,
    });
    db = await connection.db(MONGO_DATABASE);

    const users = db.collection(MONGO_COLLECTION);
    await users.deleteMany({});
    
    const dbAdapter = await EzAuthMongoDBAdapter({ db, collection: MONGO_COLLECTION });

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

  });

  afterAll(async () => {
    await connection.close();
  });

  // REGISTRATION
  it("USER REGISTER - NO PASSWORD", async () => {

    const email = faker.internet.email();

    const { user } = await auth.register({
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

  });
  it("USER REGISTER - PASSWORD", async () => {

    const email = faker.internet.email();

    const { user } = await auth.register({
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

  });
  it("USER REGISTER - ALREADY EXISTS", async () => {

    const email = faker.internet.email();

    await auth.register({
      type: "email",
      login: email,
      password: "123123",
    });

    await expect(auth.register({
      type: "email",
      login: email,
      password: "123123",
    })).rejects.toEqual({ code: auth.errors.user_already_exists });

  });

  // LOGIN PASSWORD
  it("USER PASSWORD LOGIN - CORRECT", async () => {

    const email = faker.internet.email();

    await auth.register({
      type: "email",
      login: email,
      password: "123123",
    });

    const { token } = await auth.loginPassword({
      login: email,
      password: "123123",
    });

    expect(() => {
      jwt.verify(token, "wrong-secret");
    }).toThrow();

    const { user } = await auth.tokenVerify({ token });

    expect(user.login).toEqual(email);

  });
  it("USER PASSWORD LOGIN - INCORRECT", async () => {

    const email = faker.internet.email();

    await auth.register({
      type: "email",
      login: email,
      password: "123123",
    });

    await expect(auth.loginPassword({
      login: email,
      password: "321321",
    })).rejects.toEqual({
      code: auth.errors.user_incorrect_password,
    });

  });
  it("USER PASSWORD LOGIN - NO PASSWORD", async () => {

    const email = faker.internet.email();

    await auth.register({
      type: "email",
      login: email,
    });

    await expect(auth.loginPassword({
      login: email,
      password: "321321",
    })).rejects.toEqual({
      code: auth.errors.user_no_password,
    });

  });
  it("USER PASSWORD LOGIN - DOESNT EXIST", async () => {

    const email = faker.internet.email();

    await expect(auth.loginPassword({
      login: email,
      password: "321321",
    })).rejects.toEqual({
      code: auth.errors.user_not_found,
    });

  });

  // LOGIN EMAIL
  it("USER EMAIL LOGIN", async () => {

    jest.setTimeout(10000);

    const login = "cpatarun@gmail.com";

    await auth.register({
      type: "email",
      login: login,
    });

    // TEST UNINITIALIZED
    await expect(auth.loginEmailComplete({ login, loginCode: "" })).rejects.toEqual({
      code: auth.errors.user_login_code_inactive,
    });

    // INIT LOGIN
    const { loginCode } = await auth.loginEmailInit({ login });

    // TEST INCORRECT CODE
    await expect(auth.loginEmailComplete({ login, loginCode: "" })).rejects.toEqual({
      code: auth.errors.user_login_code_incorrect,
    });

    // TEST CORRECT CODE & VERIFY TOKEN
    const { token } = await auth.loginEmailComplete({ login, loginCode });

    const { user } = await auth.tokenVerify({ token });

    expect(user.login).toEqual(login);

  });
  it("USER EMAIL LOGIN - WRONG TYPE", async () => {

    const login = "+61466986992";

    await auth.register({
      type: "phone",
      login: login,
    });

    await expect(auth.loginEmailInit({ login })).rejects.toEqual({
      code: auth.errors.user_incorrect_login_type,
    });

  });

  // EMAIL VERIFICATION
  it("USER EMAIL VERIFICATION", async () => {

    jest.setTimeout(10000);

    const login = "cpatarun@gmail.com";

    // TEST INACTIVE
    await expect(auth.emailVerificationComplete({
      login: login,
      verificationCode: "123123",
    })).rejects.toEqual({
      code: auth.errors.user_verification_inactive,
    });

    // INIT RESET
    const { verificationCode } = await auth.emailVerificationInit({ login });

    // TEST INCORRECT CODE
    await expect(auth.emailVerificationComplete({
      login: login,
      verificationCode: "123123",
    })).rejects.toEqual({
      code: auth.errors.user_verification_incorrect,
    });

    // TEST CORRECT CODE & VERIFY CHANGE
    await auth.emailVerificationComplete({ login, verificationCode });

    const user = await auth.db.userFindByLogin(login);

    expect(user!.verified).toEqual(true);

  });

  // LOGIN REVOKE
  it("USER REVOKE LOGIN", async () => {

    const login = faker.internet.email();

    await auth.register({
      type: "email",
      login: login,
      password: "123123",
    });

    const { token } = await auth.loginPassword({
      login: login,
      password: "123123",
    });

    const { user } = await auth.tokenVerify({ token });

    expect(user.login).toEqual(login);

    await auth.tokenRevoke({ login });

    await expect(auth.tokenVerify({ token })).rejects.toEqual({
      code: auth.errors.user_login_state_invalid,
    });

  });

  // RESET PASSWORD
  it("USER RESET PASSWORD", async () => {

    jest.setTimeout(10000);

    const login = faker.internet.email();

    const { user } = await auth.register({
      type: "email",
      login: login,
      password: "123123",
    });

    // INIT RESET
    const { passwordResetCode } = await auth.resetPasswordInit({ login });

    // TEST INCORRECT CODE
    await expect(auth.resetPasswordComplete({
      login: login,
      password: "123123",
      passwordResetCode: "",
    })).rejects.toEqual({
      code: auth.errors.user_password_reset_incorrect,
    });

    // TEST CORRECT CODE & VERIFY CHANGE
    await auth.resetPasswordComplete({
      login: login,
      password: "123123",
      passwordResetCode: passwordResetCode,
    });

    const updatedUser = await auth.db.userFindByLogin(login);

    expect(updatedUser!.password).not.toEqual(user!.password);

  });

  // UPDATES & DELETION
  it("USER UPDATE LOGIN", async () => {

    const login = faker.internet.email();
    const newLogin = faker.internet.email();
    const password = "123123";

    await auth.register({
      type: "email",
      login: login,
      password: "123123",
    });

    await auth.updateLogin({ login, newLogin });

    const { token } = await auth.loginPassword({
      login: newLogin,
      password: password,
    });

    const { user } = await auth.tokenVerify({ token });

    expect(user.login).toEqual(newLogin);

  });
  it("USER UPDATE PASSWORD", async () => {

    const login = "cpatarun@gmail.com";
    const password = "123123";

    const user = await auth.db.userFindByLogin(login);

    await auth.updatePassword({ login, password });

    const updatedUser = await auth.db.userFindByLogin(login);

    expect(user!.password).not.toEqual(updatedUser!.password);
    expect(user!.login_state).not.toEqual(updatedUser!.login_state);

  });
  it("USER UPDATE PROFILE", async () => {

    const login = "cpatarun@gmail.com";

    const profile = {
      organisation_id: nanoid(),
    };

    const user = await auth.db.userFindByLogin(login);

    await auth.updateProfile({ login, profile });

    const updatedUser = await auth.db.userFindByLogin(login);

    expect(updatedUser!.profile).toEqual(profile);
    expect(user!.profile).not.toEqual(updatedUser!.profile);

  });
  it("USER REMOVE", async () => {

    const login = faker.internet.email();

    await auth.register({
      type: "email",
      login: login,
    });

    await auth.removeUser({ login });

    const user = await auth.db.userFindByLogin(login);

    expect(user).toEqual(null);

  });

});
