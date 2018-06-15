const jwt = require('jsonwebtoken');
const UID = require('../../utils/uid.utils');

const ENDPOINT = 'http://localhost:3000';

const client = {
	clientId: 'fakeClient',
	clientSecret: 'fakeSecret',
	isTrusted: true
}

const errorLogger = (logger, method) => {
	return (err) => {
		if (typeof err === 'string') {
			err = new Error(err);
		}
		logger.error(`Error in ${method}: `, err);
		return err;
	}
}

/**
 * @name getAuthTokens
 * @description Exchange user credentials for auth tokens
 * @description Get VistA auth tokens from user credential params
 * @param {Express.req} req - Express request object
 * @param {Winston} logger - Winston logger
 * @return {Promise}
 */
module.exports.getAuthTokens = (req, logger) => new Promise((resolve, reject) => {
	logger.info('Auth >>> getAuthTokens');
	// Parse the required params, TODO: these are validated by sanitizeMiddleware in core
	const logError = errorLogger(logger, 'Auth.getAuthTokens');
	const {
		userId,
		facilityId
	} = req.params;
	request(ENDPOINT)
		.post('/auth')
		.send({
			userId,
			facilityId
		})
		.set('Content-Type', 'application/x-www-form-urlencoded')
		.end((err, res) => {
			if (err) {
				return reject(logError(err));
			}
			const {
				'x-access-token': accessToken,
				'x-refresh-token': refreshToken
			} = res.header;
			if (!accessToken) {
				return reject(logError('Missing required access token in result'));
			}
			resolve({
				accessToken,
				refreshToken
			})
		});
});

module.exports.refreshTokens = (req, logger) => new Promise((resolve, reject) => {
	logger.info('Auth >>> refreshTokens');
	const logError = errorLogger(logger, 'Auth.refreshToken');
	const {
		'x-refresh-token': token
	} = req.header;
	if (!token) {
		return reject(logError('Valid refresh token is required.'));
	}
	request(ENDPOINT)
		.post('/auth/refreshToken')
		.set('Content-Type', 'application/x-www-form-urlencoded')
		.set('x-refresh-token', token)
		.end((err, res) => {
			if (err) {
				return reject(logError(err));
			}
			const {
				'x-access-token': accessToken,
				'x-refresh-token': refreshToken
			} = res.header;
			if (!accessToken) {
				return reject(logError('Missing required access token in result'));
			}
			resolve({
				accessToken,
				refreshToken
			})
		});
});

/**
 * @name authorizeCode
 * @description Authorize the request and return a signed code to be exchanged for a token
 * @param {Winston} logger - Winston logger
 * @param {Object} config - FHIR Core server config object
 * @param {Object} options - Necessary options for generating the code
 * @return {Promise}
 */
module.exports.authorization = (req, logger, config, options) => new Promise((resolve, reject) => {

	logger.info('OAuth >>> generateCode');
	logger.info(options);
	let { iss, launch, scope } = options;

	let incomingJwt = launch && launch.replace(/=/g, '');

	// Prepare our code object for signing
	let code = {
		context: incomingJwt && jwt.decode(incomingJwt) || {},
		jti: UID.getUid(36),
		aud: client.clientId,
		iss: iss,
		scope: scope
	};

	resolve(jwt.sign(code, client.clientSecret, { expiresIn: '5m' }));
});

/**
 * @name generateToken
 * @description Authorize the request and return a signed code to be exchanged for a token
 * @param {Winston} logger - Winston logger
 * @param {Object} config - FHIR Core server config object
 * @param {Object} code - Returns a JsonWebToken from a signed code
 * @return {Promise}
 */
module.exports.token = (req, logger, config, code, secret) => new Promise((resolve, reject) => {
	logger.info('OAuth >>> generateToken');

	// decode token
	const decodedToken = jwt.decode(code, { complete: true });

	if (!secret && client.isTrusted) {
		secret = client.clientSecret;
	}

	// Verify the token
	jwt.verify(code, secret, (err, decoded) => {
		if (err) {
			logger.error('Error verifying token in OAuth.generateToken: ', err);
			reject(err);
		}

		// If offline, attach a refresh token
		if (decoded.scope.indexOf('offline_access') >= -1) {
			decoded.context.refresh_token = jwt.sign(decoded, secret);
		}

		// Create our token object
		let token = Object.assign({}, decoded.context, {
			token_type: 'bearer',
			expires_in: 3600,
			scope: decoded.scope,
			aud: decoded.aud,
			iss: decoded.iss,
			jti: decoded.jti
		});

		// Create an access token that expires in one hour
		token.access_token = jwt.sign(token, secret, { expiresIn: '1h' });

		resolve(token);
	})
	.catch(reject);
});