const fp = require("fastify-plugin");
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
					payload = jwt.verify(token, process.env.SALT || 'salt');
			} catch (err) {
					throw new Error(`${err.name} ${err.message} for ${entity}`);
			}

			// console.log(payload.entityID);
			// TODO find token entity
			//if (!tokenTentity) throw new error('Token entity not found');
			// TODO Implement rights check
			// if (roles && !roles.includes(entny.role)) throw new error('You have no permission to access ${entity}');
	}

	async function checkAccess(request, item) {
			if (item.schema) {
					const schema = item.schema;
					// TODO extend rule for more x-auth-type
					if (schema.body['x-auth-type'] === "Basic") {
							await checkJWT(request, schema.operationId);
					}
					if (schema && schema.body) {
							const properties = schema.body.properties;
							for (const key in properties) {
									if (!properties.hasOwnProperty(key)) continue;
									// TODO extend rule for more x-auth-type
									if (properties[key]['x-auth-type'] === "Basic") {
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
		      await checkAccess(request, item);
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
