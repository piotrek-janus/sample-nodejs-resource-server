import * as jose from 'jose'

const ErrNoConfig = 'No configuration provided'
const ErrNoIssuer = 'No issuer provided'
const ErrNoAudience = 'No audience provided'

const ErrNoToken = 'No token provided'
const ErrMissingScope = 'Missing scope'

export const createOAuthJWTValidator = async function(config) {
    if (!config) {
        throw new Error(ErrNoConfig)
    }

    const { issuer, audience, wellKnown } = config

    if (!wellKnown && !issuer) {
        throw new Error(ErrNoIssuer)
    }

    if (!audience) {
        throw new Error(ErrNoAudience)
    }

    if (wellKnown) {
        const response = await fetch(wellKnown);
        const data = await response.json();

        config = {
            ...data,
            ...config
        }
    } 

    const jwks = jose.createRemoteJWKSet(new URL(config.jwks_uri))

    console.log(jwks)

    return function(scope) {
        return async function (req, res, next) {
            let token = req.headers['authorization']
            if (!token) {
                return unauthenticated(res, ErrNoToken)
            }

            token = token.replace('Bearer ', '')
            
            try {
                const { payload } = await jose.jwtVerify(token, jwks, {
                    issuer: config.issuer,
                    audience: config.audience,
                  })
                    
                if (scope && !payload.scp.includes(scope)) {
                    return unauthorized(res, ErrMissingScope)
                }

                req.token = payload
            } catch (err) {
                if (err.code === 'ERR_JWS_VERIFICATION_FAILED') {
                    return unauthenticated(res, err.message)
                } else {
                    return unauthorized(res, err.message)
                }
            }

            try {    
                await fetch(config.userinfo_endpoint, {
                    headers: {
                        "Authorization": `Bearer ${token}`
                    }
                })
            } catch (err) {
                if (err.status === 401) {
                    return unauthenticated(res, err.message)
                }

                return failure(res, err.message)
            }
            
            next()
        }
    }
}

function unauthenticated(res, message) {
    res.status(401).json({ error: message })
}

function unauthorized(res, message) {
    res.status(403).json({ error: message })
}

function failure(res, message) {
    res.status(500).json({ error: message })
}