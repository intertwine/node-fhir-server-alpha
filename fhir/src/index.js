const fhirServerCore = require('@asymmetrik/node-fhir-server-core');
const asyncHandler = require('./lib/async-handler');

const {
	fhirServerConfig
} = require('./config');

let main = async function () {

	// Start our FHIR server
	let [ serverErr, server ] = await asyncHandler(fhirServerCore(fhirServerConfig));

	if (serverErr) {
		console.error(serverErr.message);
		process.exit(1);
	}

	server.logger.info('FHIR Server successfully started.');
};

main();
