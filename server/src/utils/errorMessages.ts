export const userNotFound = (functionSignature: string, id: string) => {
    return `${functionSignature}: User with id '${id}' was not found`;
}

export const articleNotFound = (functionSignature: string, id: string) => {
    return `${functionSignature}: Article with id '${id}' was not found`;
}

export const objectIdNotValid = (functionSignature: string, id: string) => {
    return `${functionSignature}: '${id}' is not a valid ObjectId`;
}

export const userNotCreated = (functionSignature: string, email: string) => {
    return `${functionSignature}: Failed to insert user with email '${email}' into database`;
}

export const userSuccessfullyCreated = (functionSignature: string, email: string) => {
    return `${functionSignature}: Successfully inserted user with email '${email}' into database`}

export const userRetrievedFromDatabase = (functionSignature: string, id: string) => {
    return `${functionSignature}: Retrieved user with id '${id}' from database`;   
}

export const allUsersRetrievedFromDatabase = (functionSignature: string) => {
    return `${functionSignature}: Retrieved all users from database`;
}

export const articleRetrievedFromDatabase = (functionSignature: string, id: string) => {
    return `${functionSignature}: Retrieved article with id '${id}' from database`;
}

export const allArticlesRetrievedFromDatabase = (functionSignature: string) => {
    return `${functionSignature}: Retrieved all articles from database`;
}

export const userDeletedFromDatabase = (functionSignature: string, id: string) => {
    return `${functionSignature}: Successfully deleted user with id '${id}' from database`;
}

export const userNotDeletedFromDatabase = (functionSignature: string, id: string): string => {
    return `${functionSignature}: Failed to delete user with id '${id}' from database`;
};

export const articleNotDeletedFromDatabase = (functionSignature: string, id: string): string => {
    return `${functionSignature}: Failed to delete article with id '${id}' from database`;
};

export const articleAddedToUser = (functionSignature: string, userId: string, articleId: string): string => {
    return `${functionSignature}: Successfully registered article with id '${articleId}' to user with id ${userId}`;
};

export const articleNotAddedToUser = (functionSignature: string, userId: string, articleId: string): string => {
    return `${functionSignature}: Failed to register article with id '${articleId}' to user with id '${userId}'`;
};

export const articleRemovedFromAuthor = (functionSignature: string, userId: string, articleId: string): string => {
    return `${functionSignature}: Successfully removed article with id '${articleId}' from user with id '${userId}'`;
};

export const articleNotRemovedFromAuthor = (functionSignature: string, userId: string, articleId: string): string => {
    return `${functionSignature}: Failed to remove article with id '${articleId}' from user with id '${userId}'`;
};

export const articleSuccessfullyCreated = (functionSignature: string, title: string): string => {
    return `${functionSignature}: Successfully created article with title '${title}'`;
};

export const articleNotCreated = (functionSignature: string, title: string): string => {
    return `${functionSignature}: Failed to create article with title '${title}'`;
};

export const allArticlesByAuthorIdRetrievedFromDatabase = (functionSignature: string, authorId: string): string => {
    return `${functionSignature}: Successfully retrieved all articles by author with id '${authorId}' from database`;
};

export const articleWithTitleAlreadyExists = (functionSignature: string, title: string): string => {
    return `${functionSignature}: An article with title '${title}' already exists`;
}

export const userWithEmailAlreadyExists = (functionSignature: string, email: string): string => {
    return `${functionSignature}: A user with email '${email}' already exists`;
}

export const userWithEmailNotFound = (functionSignature: string, email: string): string => {
    return `${functionSignature}: User with email '${email}' not found`;
}

export const validatedUserWithEmail = (functionSignature: string, email: string): string => {
    return `${functionSignature}: User with email '${email}' was validated`;
}

export const userWithUsernameNotFound = (functionSignature: string, username: string): string => {
    return `${functionSignature}: User with username '${username}' not found`;
}

export const validatedUserWithUsername = (functionSignature: string, username: string): string => {
    return `${functionSignature}: User with username '${username}' was validated`;
}

export const articlesMatchingSearchSuccessfullyRetrieved = (functionSignature: string, searchTerm: string): string => {
    return `${functionSignature}: Articles matching the search term ${searchTerm} were successfully retrieved`;
}