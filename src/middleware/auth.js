const JWT = require('jsonwebtoken');
const config = require('../config');
const { responseHandler } = require('../helpers');

const auth = (req, res, next) => {
  const token = req.header('x-auth-token');

  // Check if no token
  if (!token) {
    return res
      .status(401)
      .json(responseHandler(false, 401, 'Sign-in required', null));
  }

  // Verify token
  try {
    const jwtVerifyKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXgAF5FkCcnCP/Wgnr4vLrwUzlOiAZfaSb71a7gzpgAySOJYq2rZ4CyP8FnRuajox58pcLiXeLPbwUMEaHEwquLVM";
    const hsSecret = process.env.JWT_SECRET || config.JWT.SECRET;
    JWT.verify(token, jwtVerifyKey, (error, decoded) => {
      if (error) {
        if (hsSecret) {
          return JWT.verify(token, hsSecret, (error2, decoded2) => {
            if (error2) {
              return res
                .status(400)
                .json(responseHandler(false, 400, 'Try again', null));
            }
            req.user = decoded2.user;
            next();
          });
        }
        return res
          .status(400)
          .json(responseHandler(false, 400, 'Try again', null));
      }
      req.user = decoded.user;
      next();
    });
  } catch (err) {
    console.error(`error: ${err}`);
    return res
      .status(500)
      .json(responseHandler(false, 500, 'Server Error', null));
  }
};

module.exports = auth;
