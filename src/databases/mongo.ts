import {Db} from "mongodb";

interface EzAuthMongoDBAdapterOptions {
  collection: string;
  db: Db;
}

export async function EzAuthMongoDBAdapter(opts: EzAuthMongoDBAdapterOptions): Promise<EzAuthDBAdapter> {

  const { db } = opts;

  const collection = db.collection(opts.collection);

  return {
    userInsert: async (user) => {
      await collection.insertOne(user);
    },
    userFindByLogin: async (login) => {
      return collection.findOne({ login });
    },
    userFindById: async (id) => {
      return collection.findOne({ _id: id });
    },
    userUpdateById: async (id, update) => {
      await collection.updateOne({ _id: id }, {
        $set: update,
      });
    },
    userUpdateByLogin: async (login, update) => {
      await collection.updateOne({ login }, {
        $set: update,
      });
    },
    userRemove: async (login) => {
      await collection.deleteOne({ login });
    },
  };

}
