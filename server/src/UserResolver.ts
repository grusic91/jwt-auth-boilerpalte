import { 
    Resolver, 
    Query, 
    Mutation, 
    Arg, 
    ObjectType, 
    Field, 
    Ctx, 
    UseMiddleware,
    Int
} from 'type-graphql';
import bcrypt from 'bcrypt';
import { User } from './entity/User';
import { MyContext } from './MyContext';
import { createRefreshToken, createAccessToken } from './auth';

import { isAuth } from './isAuth';
import { sendRefreshToken } from './sendRefreshToken';
import { getConnection } from 'typeorm';

@ObjectType()
class LoginResponse {
    @Field()
    accessToken: string
}

@Resolver()
export class UserResolvers {
    @Query(() => String)
    hello() {
        return 'hi!'
    }

    /* protected route 
     -> check if access token is in the header
     -> pass the function in middleware that gets the access to the variables and the context
     it can check whether user should be have access to this
    */
    @Query(() => String)
    @UseMiddleware(isAuth)
    beye(
        @Ctx() {payload}: MyContext
    ) {
        console.log(payload);
        return `your user id is: ${payload!.userId}`;
    }

    @Query(() => [User])
    users() {
        return User.find()
    }

    @Mutation(() => Boolean)
    async revokeRefreshTokensForUser(
        @Arg('userId', () => Int) userId: number
    ) {
        await getConnection()
        .getRepository(User)
        .increment({id: userId}, 'tokenVersion', 1);

        return true;
    }

    /* LOGIN LOGIC */
    @Mutation(() => LoginResponse)
    async login(
        @Arg("email") email: string,
        @Arg("password") password: string,
        @Ctx() {res}: MyContext
    ) : Promise<LoginResponse> {
        // check if the user already exist
        const user = await User.findOne({where: {email}});
        if (!user) {
            throw new Error('Invalid login, could not find user');
        }

        // validate password
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            throw new Error("Wrong password!")
        }

        // successful login ->
        sendRefreshToken(res, createRefreshToken(user));

        return {
            // create token so user can state logged in
            accessToken: createAccessToken(user)
        }
    }

    /* REGISTER LOGIC */
    @Mutation(() => Boolean)
    async register(
        @Arg('email') email: string,
        @Arg('password') password: string,
    ) {
        
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        try {
            await User.insert({
                email,
                password: hashedPassword
            });
        } catch (err) {
            console.log(err);
            return false;
        }        
        return true
    }
}