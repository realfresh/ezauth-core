import { Db } from "mongodb";
interface EzAuthMongoDBAdapterOptions {
    collection: string;
    db: Db;
}
export declare function EzAuthMongoDBAdapter(opts: EzAuthMongoDBAdapterOptions): Promise<EzAuthDBAdapter>;
export {};
