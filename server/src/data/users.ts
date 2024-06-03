import validator, { trim } from "validator";
import bcrypt from "bcrypt";
import { getFunctionSignature } from "../utils/helpers";
import { getUserCollection } from "../configs/mongoCollections";
import { ObjectId } from "mongodb";
import { User } from "../model/user";
import * as ErrorMessages from "../utils/errorMessages";

export const createUser = async (email: string, username: string, password: string): Promise<User> => {
    const functionSignature: string = getFunctionSignature("CreateUser");
    email = validator.trim(email);
    username = validator.trim(username);

    if (!validator.isEmail(email)) {
        throw `${functionSignature}: '${email}' is not a valid email`;
    }
    if (!validator.isAlphanumeric(username)) {
        throw `${functionSignature}: '${username}' is not a valid username`;
    }
    if (!validator.isStrongPassword(password)) {
        throw `${functionSignature}: '${password}' is not a valid password`;
    }

    const user: User = {
        email,
        username,
        password: await bcrypt.hash(password, 16)
    };

    const userCollection = await getUserCollection();
    const emailInUse = await userCollection.findOne({email: email});
    if(emailInUse){
        throw ErrorMessages.userWithEmailAlreadyExists(functionSignature, email);
    }

    const output = await userCollection.insertOne(user);
    if (!output.acknowledged || !output.insertedId) {
        throw ErrorMessages.userNotCreated(functionSignature, email);
    }
    console.log(ErrorMessages.userSuccessfullyCreated(functionSignature, email));
    return cleanUserObject(await userCollection.findOne({ _id: output.insertedId }));
};

export const getUserById = async (id: string): Promise<User> => {
    const functionSignature: string = getFunctionSignature("GetUserById");
    if (!ObjectId.isValid(id)) {
        throw ErrorMessages.objectIdNotValid(functionSignature, id);
    }
    const userCollection = await getUserCollection();
    const user: User = await userCollection.findOne({ _id: new ObjectId(id) });
    if (!user) {
        throw ErrorMessages.userNotFound(functionSignature, id);
    }
    console.log(ErrorMessages.userRetrievedFromDatabase(functionSignature, id));
    return cleanUserObject(user);
};

export const getAllUsers = async (): Promise<User[]> => {
    const functionSignature: string = getFunctionSignature("GetAllUsers");
    const userCollection = await getUserCollection();
    const users: User[] = await userCollection.find({}).toArray();
    console.log(ErrorMessages.allUsersRetrievedFromDatabase(functionSignature));
    return cleanUserObjects(users);
};

export const deleteUserById = async (id: string): Promise<User> => {
    const functionSignature: string = getFunctionSignature("DeleteUserById");
    if (!ObjectId.isValid(id)) {
        throw ErrorMessages.objectIdNotValid(functionSignature, id);
    }
    const userCollection = await getUserCollection();
    const user: User = await userCollection.findOne({ _id: new ObjectId(id) });
    if (!user) {
        throw ErrorMessages.userNotFound(functionSignature, id);
    }
    const result = await userCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount !== 1) {
        throw ErrorMessages.userNotDeletedFromDatabase(functionSignature, id);
    }
    return cleanUserObject(user);
};

export const addArticleToAuthor = async (userId: string, articleId: string): Promise<User> => {
    const functionSignature: string = getFunctionSignature("AddArticleToAuthor");
    if (!ObjectId.isValid(userId)) {
        throw ErrorMessages.objectIdNotValid(functionSignature, userId);
    }
    if (!ObjectId.isValid(articleId)) {
        throw ErrorMessages.objectIdNotValid(functionSignature, articleId);
    }
    const userCollection = await getUserCollection();
    const updateResult = await userCollection.updateOne(
        { _id: new ObjectId(userId) },
        { $addToSet: { articles: articleId } }
    );
    if (updateResult.modifiedCount !== 1) {
        throw ErrorMessages.articleNotAddedToUser(functionSignature, userId, articleId);
    }
    console.log(ErrorMessages.articleAddedToUser(functionSignature, userId, articleId));
    return cleanUserObject(await userCollection.findOne({_id: new ObjectId(userId)}));
};

export const checkUserWithEmail = async(email: string, password: string): Promise<User> => {
    const functionSignature: string = getFunctionSignature("CreateUser");
    email = trim(email);
    password = await bcrypt.hash(trim(password), 16);
    if (!validator.isEmail(email)) {
        throw `${functionSignature}: '${email}' is not a valid email`;
    }
    const userCollection = await getUserCollection();
    const users: [User] = await userCollection.find({email: email}).toArray();
    for(let i = 0; i < users.length; i++){
        const user: User = users[i];
        if(await bcrypt.compare(user.password, password)){
            console.log(ErrorMessages.validatedUserWithEmail(functionSignature, email));
            return cleanUserObject(user);
        }
    }
    throw ErrorMessages.userWithEmailNotFound(functionSignature, email);
    
}

export const checkUserWithUsername = async(username: string, password: string): Promise<User> => {
    const functionSignature: string = getFunctionSignature("CheckUserWithUsername");
    username = trim(username);
    password = trim(password)
    if (!validator.isAlphanumeric(username)) {
        throw `${functionSignature}: '${username}' is not a valid username`;
    }
    const userCollection = await getUserCollection();
    const users: [User] = await userCollection.find({username: username}).toArray();
    for(let i = 0; i < users.length; i++){
        const user: User = users[i];
        if(await bcrypt.compare(password, user.password)){
            console.log(ErrorMessages.validatedUserWithUsername(functionSignature, username));
            return cleanUserObject(user);
        }
    }
    throw ErrorMessages.userWithUsernameNotFound(functionSignature, username);
}

const cleanUserObject = (userObject: User): User => {
    userObject._id = userObject._id.toString();
    return userObject;
};

const cleanUserObjects = (userObjects: User[]): User[] => {
    for (let i = 0; i < userObjects.length; i++) {
        userObjects[i] = cleanUserObject(userObjects[i]);
    }
    return userObjects;
};