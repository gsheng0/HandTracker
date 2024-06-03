import { dbConnection } from './mongoConnections.js';

const getCollectionFn = (collection: any) => {
  let _col: any = undefined;

  return async () => {
    if (!_col) {
      const db = await dbConnection();
      _col = await db.collection(collection);
    }

    return _col;
  };
};
export const getUserCollection = getCollectionFn("users");