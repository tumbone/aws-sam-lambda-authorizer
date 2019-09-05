const AWS = require('aws-sdk');
const documentClient = new AWS.DynamoDB.DocumentClient();
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const request = require('request');

const getItem = (tableName, keyName, keyValue) => {
  const params = {
    TableName: tableName,
    Key: { [keyName]: keyValue }
  }
  return new Promise((resolve, reject) => {
    documentClient.get(params, (err, data) => {
      if (err) reject(err);
      resolve(data);
    })
  });
}

const getJWKs = async (jwksPath) => {
  return new Promise((resolve, reject) => {
    request({ url: jwksPath, json: true }, (error, response, body) => {
      if (error || response.statusCode !== 200) {
        console.log(error);
        reject(new Error(
          'Error while getting JWKs: ' + error));
      }
      resolve(body['keys']);
    });
  });
};

const verifyTokenExpiry = async (jwtToken, pem, issuer) => {
  return new Promise((resolve, reject) => {
    jwt.verify(jwtToken, pem, { issuer }, function (err, result) {
      if (err) {
        switch (err.name) {
          case 'TokenExpiredError':
            reject(new Error('JWT Token Expired.'));
            break;
          case 'JsonWebTokenError':
            reject(new Error('Invalid JWT Token.'));
            break;
          default:
            reject(new Error(
              'Token verification failure. ' + JSON.stringify(err, null, 2)));
            break;
        }
      } else {
        resolve(result)
      }
    });
  });
}

const validateIdToken = async (idToken, cognitoAwsRegion, cognitoUserPoolId, cognitoAppClientId) => {
  try {
    const decodedJwt = jwt.decode(idToken, { complete: true });
    if (!decodedJwt) throw new Error('Invalid JWT token');
    const pathToJWKs = `https://cognito-idp.${cognitoAwsRegion}.amazonaws.com/${cognitoUserPoolId}/.well-known/jwks.json`;
    // Fail if token issure is invalid
    if (decodedJwt.payload.iss !== `https://cognito-idp.${cognitoAwsRegion}.amazonaws.com/${cognitoUserPoolId}`) {
      throw new Error('Invalid issuer: ' + decodedJwt.payload.iss);
    }
    // Reject the jwt if it's not an id token
    if (!(decodedJwt.payload.token_use === 'id')) {
      throw new Error('Invalid token_use: ' + decodedJwt.payload.token_use);
    }
    // Fail if token audience is invalid
    if (decodedJwt.payload.aud !== cognitoAppClientId) {
      throw new Error('Invalid aud: ' + decodedJwt.payload.aud);
    }
    const jwks = await getJWKs(pathToJWKs);
    const jwkItem = jwks.find(item => item.kid === decodedJwt.header.kid);
    if (!jwkItem) throw new Error('Invalid kid: ' + decodedJwt.header.kid);
    const jwk = { kty: jwkItem.kty, n: jwkItem.n, e: jwkItem.e };
    const pem = jwkToPem(jwk);
    const verifyTokenExpiryResult = await verifyTokenExpiry(idToken, pem, decodedJwt.payload.iss);
    return verifyTokenExpiryResult;
  } catch (error) {
    return Promise.reject(error);
  }
}

// Help function to generate an IAM policy
const generatePolicy = (principalId, effect, resource) => {
  let authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    let policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    let statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
}

exports.handler = async (event) => {
  let response = {};
  try {
    const validateIdTokenResult = await validateIdToken(event.authorizationToken, process.env.COGNITO_AWS_REGION, process.env.COGNITO_USER_POOL_ID, process.env.COGNITO_APP_CLIENT_ID);
    // const allowedGroups = await getItem('Vwpmw-Core-Api-Authorizer', 'MethodArn', event.methodArn);
    response = generatePolicy(validateIdTokenResult.sub, 'Allow', event.methodArn);
  } catch (error) {
    console.log(error);
    response = generatePolicy('user', 'Deny', event.methodArn);
  }
  return response;
};