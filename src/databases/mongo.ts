import {Db} from "mongodb";
import {DBAdapter, User, UserQuery} from "../types";

interface EzAuthMongoDBAdapterOptions {
  collection: string;
  db: Db;
}

function extractFilterFromQuery({ _id, username, email, phone }: UserQuery) {

  if (!_id && !username && !email && !phone) {
    throw new Error("Missing filter property in Mongo find function");
  }

  const filter: UserQuery = {};

  if (_id) {
    filter._id = _id;
  }
  else if (username) {
    filter.username = username;
  }
  else if (email) {
    filter.email = email;
  }
  else if (phone) {
    filter.phone = phone;
  }

  const orFilter: { $or: Array<Partial<User>> } = { $or: [] };

  if (_id) {
    orFilter.$or.push({ _id });
  }
  else if (username) {
    orFilter.$or.push({ username });
  }
  else if (email) {
    orFilter.$or.push({ email });
  }
  else if (phone) {
    orFilter.$or.push({ phone });
  }

  return { filter, orFilter };

}

export async function EzAuthMongoDBAdapter(opts: EzAuthMongoDBAdapterOptions): Promise<DBAdapter> {

  const { db } = opts;

  const collection = db.collection(opts.collection);

  return {
    insert: async (user) => {
      await collection.insertOne(user);
    },
    find: async (query, checkAll) => {
      const { filter, orFilter } = extractFilterFromQuery(query);
      return collection.findOne(checkAll ? orFilter : filter);

    },
    update: async (query, update) => {
      const { filter } = extractFilterFromQuery(query);
      await collection.updateOne(filter, { $set: update });
    },
    remove: async (query) => {
      const { filter } = extractFilterFromQuery(query);
      await collection.deleteOne(filter);
    },
  };

}
