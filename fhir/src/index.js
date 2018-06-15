const FHIRServer = require('@asymmetrik/node-fhir-server-core');

const {
	fhirServerConfig
} = require('./config');

let main = function () {

	let server = FHIRServer.initialize(fhirServerConfig);
	server.logger.info('FHIR Server successfully validated.');
	server.listen(3000, () =>
		server.logger.info('FHIR Server listening on localhost:' + 3000)
	);

};

main();
