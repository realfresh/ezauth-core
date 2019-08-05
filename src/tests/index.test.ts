import fs from "fs";
import path from "path";
import jwt from "jsonwebtoken";
import faker from "faker";
import nanoid from "nanoid";
import {Db, MongoClient} from "mongodb";
import EzAuth, {EzAuthMongoDBAdapter} from "..";
import {User} from "../types";

require("dotenv").config({
  path: ".env.test",
});

const ES512_PRIVATE_KEY = fs.readFileSync(path.join(__dirname, "/../../keys/es512-private.pem"), "utf8");
const ES512_PUBLIC_KEY = fs.readFileSync(path.join(__dirname, "/../../keys/es512-public.pem"), "utf8");
const HMAC_SECRET_KEY = "super-secret";
const MONGO_URL = process.env.MONGO_URL;
const MONGO_DATABASE = process.env.MONGO_DATABASE;
const MONGO_COLLECTION = process.env.MONGO_COLLECTION;

interface CustomUser extends User {
  test_field: number;
}

describe("EZAUTH TESTS", () => {

  if (!MONGO_URL || !MONGO_DATABASE || !MONGO_COLLECTION) {
    throw new Error("Please supply process.env with MONGO_URL, MONGO_DATABASE, MONGO_COLLECTION");
  }

  let connection: MongoClient;
  let db: Db;
  let auth: EzAuth<CustomUser>;

  beforeAll(async () => {

    connection = await MongoClient.connect(MONGO_URL, {
      useNewUrlParser: true,
    });
    db = await connection.db(MONGO_DATABASE);

    const users = db.collection(MONGO_COLLECTION);
    await users.deleteMany({});

    const dbAdapter = await EzAuthMongoDBAdapter<CustomUser>({ db, collection: MONGO_COLLECTION });

    auth = new EzAuth({
      tokenAlgorithm: "ES512", // "HS512",
      tokenSecretKey: ES512_PRIVATE_KEY,
      tokenPublicKey: ES512_PUBLIC_KEY,
      db: dbAdapter,
    });

  });

  afterAll(async () => {
    await connection.close();
  });

  // MONGO ADAPTER

  // REGISTRATION
  it("REGISTER - NO PASSWORD", async () => {

    const email = faker.internet.email();

    const { user } = await auth.register({
      email: email,
    });

    expect(typeof user._id).toEqual("string");
    expect(typeof user.created).toEqual("number");
    expect(user.username).toEqual(undefined);
    expect(user.email).toEqual(email);
    expect(user.phone).toEqual(undefined);
    expect(typeof user.auth_state).toEqual("string");
    expect(user.password).toEqual(null);
    expect(user.data).toEqual({});

  });
  it("REGISTER - PASSWORD", async () => {

    const email = faker.internet.email();

    const { user } = await auth.register({
      email: email,
      password: "123123",
    });

    expect(typeof user._id).toEqual("string");
    expect(typeof user.created).toEqual("number");
    expect(user.username).toEqual(undefined);
    expect(user.email).toEqual(email);
    expect(user.phone).toEqual(undefined);
    expect(typeof user.auth_state).toEqual("string");
    expect(typeof user.password).toEqual("string");
    expect(user.data).toEqual({});

  });
  it("REGISTER - MULTI ACCOUNT", async () => {

    const username = faker.internet.email();
    const email = faker.internet.email();
    const phone = faker.phone.phoneNumber();
    const password = "123123";

    const { user } = await auth.register({ username, email, phone, password });

    expect(user.username).toEqual(username);
    expect(user.email).toEqual(email);
    expect(user.phone).toEqual(phone);

    await auth.loginPassword({ username, password });
    await auth.loginPassword({ email, password });
    await auth.loginPassword({ phone, password });

  });
  it("REGISTER - IDENTIFIER CONFLICTS", async () => {

    jest.setTimeout(10000);

    const justEmail = faker.internet.email();

    await auth.register({
      email: justEmail,
      password: "123123",
    });

    await expect(auth.register({
      email: justEmail,
    })).rejects.toEqual({ code: auth.errors.register_already_exists });

    const first = {
      username: faker.internet.userName(),
      email: faker.internet.email(),
      phone: faker.phone.phoneNumber(),
    };
    const second = {
      username: faker.internet.userName(),
      phone: faker.phone.phoneNumber(),
    };
    const third = {
      email: faker.internet.email(),
      phone: faker.phone.phoneNumber(),
    };
    const fourth = {
      phone: faker.phone.phoneNumber(),
    };

    await auth.register(first);
    await auth.register(second);
    await auth.register(third);
    await auth.register(fourth);

    await expect(auth.register(first)).rejects.toEqual({ code: auth.errors.register_already_exists });
    await expect(auth.register(second)).rejects.toEqual({ code: auth.errors.register_already_exists });
    await expect(auth.register(third)).rejects.toEqual({ code: auth.errors.register_already_exists });
    await expect(auth.register(fourth)).rejects.toEqual({ code: auth.errors.register_already_exists });

    await expect(auth.register({
      username: first.username,
      phone: fourth.phone,
    })).rejects.toEqual({ code: auth.errors.register_already_exists });

    await expect(auth.register({
      username: first.username,
    })).rejects.toEqual({ code: auth.errors.register_already_exists });

    await expect(auth.register({
      email: third.email,
    })).rejects.toEqual({ code: auth.errors.register_already_exists });

    await expect(auth.register({
      phone: second.phone,
    })).rejects.toEqual({ code: auth.errors.register_already_exists });

  });

  // LOGIN PASSWORD
  it("PASSWORD LOGIN", async () => {

    const email = faker.internet.email();

    await auth.register({
      email: email,
      password: "123123",
    });

    // WRONG PASSWORD
    await expect(auth.loginPassword({
      email: email,
      password: "321321",
    })).rejects.toEqual({
      code: auth.errors.login_password_incorrect,
    });

    // CORRECT PASSWORD
    const { token } = await auth.loginPassword({
      email: email,
      password: "123123",
    });

    expect(() => {
      jwt.verify(token, "wrong-secret");
    }).toThrow();

    const { decoded } = await auth.tokenVerify({ token });

    expect(decoded.email).toEqual(email);

  });
  it("PASSWORD LOGIN - NO PASSWORD", async () => {

    const email = faker.internet.email();

    await auth.register({ email });

    await expect(auth.loginPassword({
      email: email,
      password: "321321",
    })).rejects.toEqual({
      code: auth.errors.login_password_none,
    });

  });
  it("PASSWORD LOGIN - USER DOESNT EXIST", async () => {

    const email = faker.internet.email();

    await expect(auth.loginPassword({
      email: email,
      password: "321321",
    })).rejects.toEqual({
      code: auth.errors.user_not_found,
    });

  });

  // TOKEN VALIDATION

  // ADDITIONAL FUNCTIONS
  it("CODE LOGIN", async () => {

    jest.setTimeout(10000);

    const email = "cpatarun@gmail.com";

    await auth.register({ email });

    // TEST UNINITIALIZED
    await expect(auth.loginCodeComplete({ email, loginCode: "" })).rejects.toEqual({
      code: auth.errors.login_code_inactive,
    });

    // INIT LOGIN
    const { loginCode } = await auth.loginCodeInit({ email });

    // TEST INCORRECT CODE
    await expect(auth.loginCodeComplete({ email, loginCode: "as213" })).rejects.toEqual({
      code: auth.errors.login_code_incorrect,
    });

    // TEST CORRECT CODE & VERIFY TOKEN
    const { token } = await auth.loginCodeComplete({ email, loginCode });

    const { decoded } = await auth.tokenVerify({ token });

    expect(decoded.email).toEqual(email);

  });
  it("EMAIL VERIFICATION", async () => {

    jest.setTimeout(10000);

    const email = "cpatarun@gmail.com";

    // TEST INACTIVE
    await expect(auth.verificationComplete({
      email: email,
      type: "email",
      code: "123123",
    })).rejects.toEqual({
      code: auth.errors.verification_inactive,
    });

    // INIT RESET
    const { code } = await auth.verificationInit({ email });

    // TEST INCORRECT CODE
    await expect(auth.verificationComplete({
      email: email,
      type: "email",
      code: "123123",
    })).rejects.toEqual({
      code: auth.errors.verification_incorrect,
    });

    // TEST CORRECT CODE & VERIFY CHANGE
    await auth.verificationComplete({ email, code, type: "email" });

    const user = await auth.db.find({ email });

    expect(user!.email_verified).toEqual(true);

  });
  it("REVOKE LOGIN", async () => {

    const email = faker.internet.email();
    const password = "123123";

    await auth.register({ email, password });

    const { token } = await auth.loginPassword({ email, password });

    const { user } = await auth.tokenVerify({ token });

    expect(user.email).toEqual(email);

    await auth.tokenRevoke({ email });

    await expect(auth.tokenVerify({ token })).rejects.toEqual({
      code: auth.errors.user_token_invalid,
    });

  });
  it("RESET PASSWORD", async () => {

    jest.setTimeout(10000);

    const email = faker.internet.email();
    const password = "123123";

    const { user } = await auth.register({ email, password });

    // TEST INACTIVE
    await expect(auth.resetPasswordComplete({
      email: email,
      password: "123123",
      code: "abc123",
    })).rejects.toEqual({
      code: auth.errors.password_reset_inactive,
    });

    // INIT RESET
    const { code } = await auth.resetPasswordInit({ email });

    // TEST INCORRECT CODE
    await expect(auth.resetPasswordComplete({
      email: email,
      password: "123123",
      code: "abc123",
    })).rejects.toEqual({
      code: auth.errors.password_reset_incorrect,
    });

    // TEST CORRECT CODE & VERIFY CHANGE
    await auth.resetPasswordComplete({ email, password, code });

    const updatedUser = await auth.db.find({ email });

    expect(updatedUser!.password).not.toEqual(user!.password);

  });

  // UPDATES & DELETION
  it("UPDATE LOGIN", async () => {

    const email = faker.internet.email();
    const newEmail = faker.internet.email();
    const otherEmail = faker.internet.email();
    const password = "123123";

    await auth.register({ email, password });

    await auth.register({ email: otherEmail });

    // CHECK SAME EMAIL
    await expect(auth.updateLogin({ email, newEmail: email })).rejects.toEqual({ code: auth.errors.update_login_already_exists });

    // CHECK OTHER EMAIL
    await expect(auth.updateLogin({ email, newEmail: otherEmail })).rejects.toEqual({ code: auth.errors.update_login_already_exists });

    // UPDATE CORRECT
    await auth.updateLogin({ email, newEmail });

    const { token } = await auth.loginPassword({ email: newEmail, password });

    const { decoded } = await auth.tokenVerify({ token });

    expect(decoded.email).toEqual(newEmail);

  });
  it("UPDATE PASSWORD", async () => {

    const email = "cpatarun@gmail.com";
    const password = "123123";

    const user = await auth.db.find({ email });

    await auth.updatePassword({ email, password });

    const updatedUser = await auth.db.find({ email });

    expect(user!.password).not.toEqual(updatedUser!.password);
    expect(user!.auth_state).not.toEqual(updatedUser!.auth_state);

  });
  it("UPDATE DATA", async () => {

    const email = "cpatarun@gmail.com";

    const data = {
      organisation_id: nanoid(),
    };

    const user = await auth.db.find({ email });

    await auth.updateData({ email, data });

    const updatedUser = await auth.db.find({ email });

    expect(updatedUser!.data).toEqual(data);
    expect(user!.data).not.toEqual(updatedUser!.data);

  });
  it("REMOVE", async () => {

    const email = faker.internet.email();

    await auth.register({ email });

    const exists = await auth.db.find({ email });

    expect(exists).not.toEqual(null);

    await auth.removeUser({ email });

    const user = await auth.db.find({ email });

    expect(user).toEqual(null);

  });

});
