import "dotenv/config";
import "reflect-metadata";
import express from 'express';
import { ApolloServer } from 'apollo-server-express';
import { buildSchema } from "type-graphql";
import { UserResolvers } from "./UserResolver";
import { createConnection } from "typeorm";
import cookieParser from 'cookie-parser';
import { verify } from "jsonwebtoken";
import { User } from "./entity/User";
import { createAccessToken, createRefreshToken } from "./auth";
import { sendRefreshToken } from "./sendRefreshToken";


/* all logic to start here */
(async () => {
    const app = express();
    app.use(cookieParser());
    app.get('/', (_req, res ) => res.send("Hello"));

    app.post("/refresh_token", async (req, res) => {
        // reed the cookie where should be refresh token
        const token = req.cookies.jid;
        if(!token) {
            return res.send({ ok: false, accessToken: ''})
        }

        // make sure that token has not get expired
        let payload: any = null;
        try {
            payload = verify(token, process.env.REFRESH_TOKEN_SECRET!);
        } catch(err) {
            console.log(err);
            return res.send({ ok: false, accessToken: ''});
        }

        // token is valid and we can send back an access token
        const user = await User.findOne({ id: payload.userId });

        if (!user) {
            return res.send({ ok: false, accessToken: ''});
        }

        // check if token version is equal to version in payload
        if (user.tokenVersion !== payload.tokenVersion) {
            return res.send({ok: false, accessToken: ""});
        }

        // whenever refresh access token refresh refresh token
        sendRefreshToken(res, createRefreshToken(user))

        return res.send({ ok: true, accessToken: createAccessToken(user)});
        
    })

    await createConnection();

    /* Define graphql  */
    const apolloServer = new ApolloServer({
        schema: await buildSchema({
            resolvers: [UserResolvers]
        }),
        context: ({ req, res }) => ({ req, res })
    });

    /* add graphql to express server 
        we can go now on http://localhost:4000/graphql
    */
    apolloServer.applyMiddleware({ app });

    app.listen(4000, () => {
        console.log("express server started");
        
    })
})()
