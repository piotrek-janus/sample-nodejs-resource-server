import express from 'express';
import cors from 'cors';
import {createOAuthJWTValidator} from './oauth.js';

const app = express()
const port = 7777

createOAuthJWTValidator(
    {
        wellKnown: "https://janus.eu.authz.cloudentity.io/janus/demo/.well-known/openid-configuration",
        audience: "hello-service",
    })
    .then(validator => {
        app.use(cors())
        app.use(express.json())
        // requires the access token to contain the scope "say-hello" to call the endpoint
        app.use(validator('say-hello'))

        app.get('/hello', (req, res) => {
            res.json({hello: req.token})
        })

        app.listen(port, () => {
            console.log(`Example app listening on port ${port}`)
        })
    })