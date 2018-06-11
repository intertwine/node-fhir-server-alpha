/**
 * @name getAuthTokens
 * @description Exchange user credentials for auth tokens
 * @description Get VistA auth tokens from user credential params
 * @param {Express.req} req - Express request object
 * @param {Winston} logger - Winston logger
 * @return {Promise}
 */

const ENDPOINT = 'localhost:3000';

const errorLogger = (logger, method) => {
	return (err) => {
		if (typeof err === 'string') {
			err = new Error(err);
		}
		logger.error(`Error in ${method}: `, err);
		return err;
	}
}

 module.exports.getAuthTokens = (req, logger) => new Promise((resolve, reject) => {
 	logger.info('Auth >>> getAuthTokens');
 	// Parse the required params, TODO: these are validated by sanitizeMiddleware in core
 	const logError = errorLogger(logger, 'Auth.getAuthTokens');
 	const { userId, facilityId } = req.params;
	request(ENDPOINT)
		.post('/auth')
		.send({ userId, facilityId })
		.set('Content-Type', 'application/x-www-form-urlencoded')
		.end((err, res) => {
			if (err) {
				return reject(logError(err));
			}
			const {
				accessToken: 'x-access-token',
				refreshToken: 'x-refresh-token'
			} = res.header;
			if (!accessToken) {
				return reject(logError('Missing required access token in result'));
			}
			resolve({ accessToken, refreshToken })
		});
 	});
 });

 module.exports.refreshTokens = (req, logger) => new Promise(resolve, reject) => {
	 logger.info('Auth >>> refreshTokens');
	 const logError = errorLogger(logger, 'Auth.refreshToken');
	 const {token: 'x-refresh-token'} = req.header;
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
				accessToken: 'x-access-token',
				refreshToken: 'x-refresh-token'
			} = res.header;
			if (!accessToken) {
				return reject(logError('Missing required access token in result'));
			}
			resolve({ accessToken, refreshToken })
		});
 }