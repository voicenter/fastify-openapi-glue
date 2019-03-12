const fp = require("fastify-plugin");
const ip = require('ip');
const jwt = require('jsonwebtoken');
const parser = require("./lib/parser");

function isObject(obj) {
  return typeof obj === "object" && obj !== null;
}

function getObject(param) {
  let data = param;
  if (typeof param === "string") {
    try {
      data = require(param);
    } catch (error) {
      throw new Error(`failed to load ${param}`);
    }
  }
  if (typeof data === "function") {
    data = data();
  }

  return data;
}

// fastify uses the built-in AJV instance during serialization, and that
// instance does not know about int32 and int64 so remove those formats
// from the responses
const unknownFormats = { int32: true, int64: true };

function stripResponseFormats(schema) {
  for (let item in schema) {
    if (isObject(schema[item])) {
      if (schema[item].format && unknownFormats[schema[item].format]) {
        schema[item].format = undefined;
      }
      stripResponseFormats(schema[item]);
    }
  }
}

async function fastifyOpenapiGlue(instance, opts) {
  const service = getObject(opts.service);
		if (!isObject(service)) {
    throw new Error("'service' parameter must refer to an object");
  }

  const config = await parser().parse(opts.specification);
  const routeConf = {};

  // AJV misses some validators for int32, int64 etc which ajv-oai adds
  const Ajv = require("ajv-oai");
  const ajv = new Ajv({
    // the fastify defaults
    removeAdditional: true,
    useDefaults: true,
    coerceTypes: true
  });

  instance.setSchemaCompiler(schema => ajv.compile(schema));

  if (config.prefix) {
    routeConf.prefix = config.prefix;
  }

		/**
		 * @param request {request}
		 * @param entity {string} name of object or field, used for error handling
		 * @return {Promise.<void>}
		 */
	async function checkJWT(request, entity) {
			if (!('authorization' in request.headers)) throw new Error(`Missing authorization header for ${entity}`);
			const token = request.headers['authorization'].split(' ')[1];
			let payload;

			// check if the token is expired or broken
			try {
					payload = jwt.verify(token, service.publicKey, {algorithm:  "RS256"});
			} catch (err) {
					throw new Error(`${err.name} ${err.message} for ${entity}`);
			}

			const {IpList, Expiration, Permissions} =  payload;

			// check that client IP in token range
			if (IpList && IpList.length) {
			  const ipInAllowedRange = IpList.some(ipRange => ip.cidrSubnet(ipRange).contains(request.req.ip));
				if (!ipInAllowedRange) throw new Error('IP address if out of range you permit for') ;
			}

			// check expiration date
				if (Expiration && (Date.parse(Expiration) < Date.now())) {
						throw new Error('Token expired') ;
				}

			// TODO Implement permissions check

	}

	async function checkAccess(request, item) {
			if (item.schema) {
					const schema = item.schema;
					// TODO extend rule for more x-auth-type
					if (item.openapiSource['x-AuthType'] === "Basic") {
							await checkJWT(request, schema.operationId);
					}
					if (schema && schema.body) {
							const properties = schema.body.properties;
							for (const key in properties) {
									if (!properties.hasOwnProperty(key)) continue;
									// TODO extend rule for more x-auth-type
									if (properties[key]['x-AuthType'] === "Basic") {
											await checkJWT(request, `${schema.operationId} ${key}`);
									}
							}
					}
			}
	}

  async function generateRoutes(routesInstance, opts) {
    config.routes.forEach(item => {
      const response = item.schema.response;
      if (response) {
        stripResponseFormats(response);
      }
      if (service[item.operationId]) {
        routesInstance.log.debug("service has", item.operationId);
        item.handler = async (request, reply) => {
		      if (service.checkToken) await checkAccess(request, item);
          return service[item.operationId](request, reply);
        };
      } else {
        item.handler = async (request, reply) => {
          throw new Error(`Operation ${item.operationId} not implemented`);
        };
      }
      routesInstance.route(item);
    });
  }

  instance.register(generateRoutes, routeConf);
}

module.exports = fp(fastifyOpenapiGlue, {
  fastify: ">=0.39.0",
  name: "fastify-openapi-glue"
});

module.exports.options = {
  specification: "examples/petstore/petstore-swagger.v2.json",
  service: "examples/petstore/service.js"
};
