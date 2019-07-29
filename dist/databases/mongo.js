"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
function EzAuthMongoDBAdapter(opts) {
    return __awaiter(this, void 0, void 0, function* () {
        const { db } = opts;
        const collection = db.collection(opts.collection);
        return {
            userInsert: (user) => __awaiter(this, void 0, void 0, function* () {
                yield collection.insertOne(user);
            }),
            userFindByLogin: (login) => __awaiter(this, void 0, void 0, function* () {
                return collection.findOne({ login });
            }),
            userFindById: (id) => __awaiter(this, void 0, void 0, function* () {
                return collection.findOne({ _id: id });
            }),
            userUpdateById: (id, update) => __awaiter(this, void 0, void 0, function* () {
                yield collection.updateOne({ _id: id }, {
                    $set: update,
                });
            }),
            userUpdateByLogin: (login, update) => __awaiter(this, void 0, void 0, function* () {
                yield collection.updateOne({ login }, {
                    $set: update,
                });
            }),
            userRemove: (login) => __awaiter(this, void 0, void 0, function* () {
                yield collection.deleteOne({ login });
            }),
        };
    });
}
exports.EzAuthMongoDBAdapter = EzAuthMongoDBAdapter;
//# sourceMappingURL=mongo.js.map